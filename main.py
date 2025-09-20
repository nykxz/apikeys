import os
import time
import json
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, redirect, url_for, jsonify, make_response
import requests
from functools import wraps
import socket
import ipaddress

app = Flask(__name__)
app.secret_key = 'supersecretkey123!'

# Configuración
ADMIN_USERNAME = "admin123"
ADMIN_PASSWORD = "admin123"
WEBHOOK_URL = "https://discord.com/api/webhooks/1395449191068729364/-KuZXZT_lKgSNSnfMugtY5wJUdQxaq7GwQIG7QgRD_UODwpBy6_Nz7XrULCaSVasktsT"
IP_ACCESS = "85.58.161.187"
BAN_TIME = 60 * 60 * 24 * 60  # 2 meses en segundos
MAX_LOGIN_ATTEMPTS = 2

# Almacenamiento en memoria
keys = {}
banned_ips = {}
login_attempts = {}
active_sessions = {}

# Estilos CSS
STYLES = """
<style>
    :root {
        --primary: #6a0dad;
        --secondary: #00ffff;
        --dark: #121212;
        --light: #f8f9fa;
    }
    
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: var(--dark);
        color: var(--light);
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
    }
    
    .container {
        background-color: rgba(18, 18, 18, 0.9);
        border-radius: 10px;
        box-shadow: 0 0 20px var(--primary);
        padding: 30px;
        width: 100%;
        max-width: 500px;
        border: 1px solid var(--primary);
    }
    
    h1, h2, h3 {
        color: var(--secondary);
        text-align: center;
        margin-bottom: 20px;
    }
    
    .form-group {
        margin-bottom: 20px;
    }
    
    label {
        display: block;
        margin-bottom: 5px;
        color: var(--secondary);
    }
    
    input, select {
        width: 100%;
        padding: 10px;
        border-radius: 5px;
        border: 1px solid var(--primary);
        background-color: rgba(255, 255, 255, 0.1);
        color: var(--light);
    }
    
    button {
        background-color: var(--primary);
        color: white;
        border: none;
        padding: 12px 20px;
        border-radius: 5px;
        cursor: pointer;
        width: 100%;
        font-weight: bold;
        transition: all 0.3s;
    }
    
    button:hover {
        background-color: #7b1fa2;
        transform: translateY(-2px);
    }
    
    .alert {
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 20px;
        text-align: center;
    }
    
    .alert-danger {
        background-color: rgba(255, 0, 0, 0.2);
        border: 1px solid red;
        color: #ff6b6b;
    }
    
    .alert-success {
        background-color: rgba(0, 255, 0, 0.2);
        border: 1px solid green;
        color: #6bff6b;
    }
    
    .key-display {
        background-color: rgba(106, 13, 173, 0.2);
        border: 1px solid var(--primary);
        padding: 15px;
        border-radius: 5px;
        word-break: break-all;
        text-align: center;
        margin: 20px 0;
        font-family: monospace;
    }
    
    .nav {
        display: flex;
        justify-content: space-around;
        margin-bottom: 30px;
    }
    
    .nav a {
        color: var(--secondary);
        text-decoration: none;
        padding: 10px;
        border-bottom: 2px solid transparent;
        transition: all 0.3s;
    }
    
    .nav a:hover, .nav a.active {
        border-bottom: 2px solid var(--secondary);
    }
    
    .key-item {
        background-color: rgba(0, 255, 255, 0.1);
        border: 1px solid var(--secondary);
        padding: 10px;
        margin-bottom: 10px;
        border-radius: 5px;
    }
    
    .key-info {
        display: flex;
        justify-content: space-between;
    }
    
    .key-actions {
        margin-top: 10px;
    }
    
    .key-actions button {
        padding: 5px 10px;
        margin-right: 5px;
        width: auto;
    }
    
    .table {
        width: 100%;
        border-collapse: collapse;
    }
    
    .table th, .table td {
        padding: 10px;
        text-align: left;
        border-bottom: 1px solid var(--primary);
    }
    
    .table th {
        color: var(--secondary);
    }
    
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
    }
    
    .badge-success {
        background-color: rgba(0, 255, 0, 0.2);
        color: #6bff6b;
    }
    
    .badge-danger {
        background-color: rgba(255, 0, 0, 0.2);
        color: #ff6b6b;
    }
    
    .badge-warning {
        background-color: rgba(255, 255, 0, 0.2);
        color: #ffff6b;
    }
</style>
"""

# Funciones de utilidad
def get_client_ip():
    # Lista de headers que pueden contener la IP real
    ip_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'CF-Connecting-IP',  # Cloudflare
        'True-Client-IP',    # Cloudflare Enterprise
        'Forwarded',
        'Proxy-Client-IP',
        'WL-Proxy-Client-IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR'
    ]
    
    # Verificar cada header posible
    for header in ip_headers:
        if header in request.headers:
            ips = request.headers[header].split(',')
            # Tomar la primera IP (el cliente original puede estar al final de la lista)
            ip = ips[0].strip()
            if ip:
                return ip
    
    # Si no se encuentra en los headers, usar remote_addr
    ip = request.remote_addr
    
    # Si es localhost (127.0.0.1 o ::1), intentar obtener la IP pública
    if ip in ('127.0.0.1', '::1'):
        try:
            # Opción 1: Usar un servicio externo para obtener la IP pública
            response = requests.get('https://api.ipify.org?format=json', timeout=3)
            if response.status_code == 200:
                return response.json().get('ip', ip)
            
            # Opción 2: Alternativa si el primer servicio falla
            response = requests.get('https://ipinfo.io/json', timeout=3)
            if response.status_code == 200:
                return response.json().get('ip', ip)
        except:
            pass
    
    return ip

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=3)
        if response.status_code == 200:
            return response.json().get('ip', 'Desconocida')
    except:
        pass
    
    try:
        response = requests.get('https://ipinfo.io/json', timeout=3)
        if response.status_code == 200:
            return response.json().get('ip', 'Desconocida')
    except:
        pass
    
    return 'Desconocida'

def is_banned(ip):
    if ip in banned_ips:
        if banned_ips[ip]['until'] > time.time():
            return True
        else:
            del banned_ips[ip]
    return False

def send_to_discord(title, description, color=0x6a0dad):
    data = {
        "embeds": [{
            "title": f"🔹 {title}",
            "description": description,
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "Key Management System"
            }
        }]
    }
    
    try:
        requests.post(WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Error enviando a Discord: {e}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        if is_banned(client_ip):
            return render_template_string(f"""
                {STYLES}
                <div class="container">
                    <h1>🔒 Acceso Bloqueado</h1>
                    <div class="alert alert-danger">
                        <p>🚫 Tu IP ({client_ip}) ha sido bloqueada por intentos fallidos de inicio de sesión.</p>
                        <p>⏳ El bloqueo expirará en 2 meses.</p>
                    </div>
                </div>
            """), 403
        
        if client_ip not in active_sessions or active_sessions[client_ip]['expires'] < time.time():
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def calculate_seconds(amount, unit):
    unit = unit.lower()
    if unit in ['dia', 'dias']:
        return amount * 86400
    elif unit in ['semana', 'semanas']:
        return amount * 604800
    elif unit in ['mes', 'meses']:
        return amount * 2592000  # 30 días
    elif unit in ['año', 'años']:
        return amount * 31536000  # 365 días
    return amount

# Rutas de la aplicación
@app.route('/')
@login_required
def index():
    client_ip = get_client_ip()
    return render_template_string(f"""
        {STYLES}
        <div class="container">
            <h1>🔑 Sistema de Gestión de Claves</h1>
            <div class="alert alert-success">
                <p>👋 Bienvenido, administrador!</p>
                <p>🖥️ Tu IP: {get_public_ip()} </p>
            </div>
            
            <div class="nav">
                <a href="{url_for('generate_key')}" class="active">🔑 Generar Clave</a>
                <a href="{url_for('manage_keys')}">🗝️ Gestionar Claves</a>
                <a href="{url_for('unban_ip')}">🔓 Desbloquear IP</a>
            </div>
            
            <h3>📊 Estadísticas</h3>
            <p>🔑 Claves activas: {len([k for k in keys if keys[k]['expires'] > time.time()])}</p>
            <p>⏳ Claves expiradas: {len([k for k in keys if keys[k]['expires'] <= time.time()])}</p>
            <p>🚫 IPs bloqueadas: {len(banned_ips)}</p>
            
            <form action="{url_for('logout')}" method="post" style="margin-top: 30px;">
                <button type="submit">🔒 Cerrar Sesión</button>
            </form>
        </div>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = get_client_ip()
    
    if is_banned(client_ip):
        return render_template_string(f"""
            {STYLES}
            <div class="container">
                <h1>🔒 Acceso Bloqueado</h1>
                <div class="alert alert-danger">
                    <p>🚫 Tu IP ({client_ip}) ha sido bloqueada por intentos fallidos de inicio de sesión.</p>
                    <p>⏳ El bloqueo expirará en 2 meses.</p>
                </div>
            </div>
        """), 403
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Resetear intentos fallidos
            if client_ip in login_attempts:
                del login_attempts[client_ip]
            
            # Crear sesión
            active_sessions[client_ip] = {
                'logged_in': True,
                'expires': time.time() + 3600  # 1 hora de sesión
            }
            
            # Log a Discord
            send_to_discord(
                "✅ Inicio de Sesión Exitoso",
                f"**IP:** `{client_ip}`\n**Usuario:** `{username}`\n**Hora:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                0x00ff00
            )
            
            return redirect(url_for('index'))
        else:
            # Registrar intento fallido
            if client_ip not in login_attempts:
                login_attempts[client_ip] = 0
            login_attempts[client_ip] += 1
            
            # Bloquear IP si supera los intentos
            if login_attempts[client_ip] >= MAX_LOGIN_ATTEMPTS:
                banned_ips[client_ip] = {
                    'reason': 'Demasiados intentos de inicio de sesión fallidos',
                    'until': time.time() + BAN_TIME
                }
                
                send_to_discord(
                    "🚫 IP Bloqueada",
                    f"**IP:** `{client_ip}`\n**Razón:** Demasiados intentos de inicio de sesión fallidos\n**Bloqueo hasta:** <t:{int(time.time() + BAN_TIME)}:F>",
                    0xff0000
                )
                
                return render_template_string(f"""
                    {STYLES}
                    <div class="container">
                        <h1>🔒 Acceso Bloqueado</h1>
                        <div class="alert alert-danger">
                            <p>🚫 Demasiados intentos fallidos. Tu IP ({client_ip}) ha sido bloqueada por 2 meses.</p>
                        </div>
                    </div>
                """), 403
            
            # Log a Discord
            send_to_discord(
                "⚠️ Intento de Inicio de Sesión Fallido",
                f"**IP:** `{client_ip}`\n**Usuario:** `{username}`\n**Intento:** {login_attempts[client_ip]}/{MAX_LOGIN_ATTEMPTS}\n**Hora:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                0xffa500
            )
            
            return render_template_string(f"""
                {STYLES}
                <div class="container">
                    <h1>🔑 Iniciar Sesión</h1>
                    <div class="alert alert-danger">
                        <p>❌ Usuario o contraseña incorrectos. Intentos restantes: {MAX_LOGIN_ATTEMPTS - login_attempts[client_ip]}</p>
                    </div>
                    <form method="post">
                        <div class="form-group">
                            <label for="username">👤 Usuario</label>
                            <input type="text" id="username" name="username" required>
                        </div>
                        <div class="form-group">
                            <label for="password">🔒 Contraseña</label>
                            <input type="password" id="password" name="password" required>
                        </div>
                        <button type="submit">🔑 Iniciar Sesión</button>
                    </form>
                </div>
            """)
    
    return render_template_string(f"""
        {STYLES}
        <div class="container">
            <h1>🔑 Iniciar Sesión</h1>
            <form method="post">
                <div class="form-group">
                    <label for="username">👤 Usuario</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">🔒 Contraseña</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">🔑 Iniciar Sesión</button>
            </form>
        </div>
    """)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    client_ip = get_client_ip()
    if client_ip in active_sessions:
        del active_sessions[client_ip]
    
    send_to_discord(
        "🔐 Sesión Cerrada",
        f"**IP:** `{client_ip}`\n**Usuario:** `{ADMIN_USERNAME}`\n**Hora:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        0x6a0dad
    )
    
    return redirect(url_for('login'))

@app.route('/generate-key', methods=['GET', 'POST'])
@login_required
def generate_key():
    client_ip = get_client_ip()
    
    if request.method == 'POST':
        duration = int(request.form.get('duration', 1))
        unit = request.form.get('unit', 'dias')
        notes = request.form.get('notes', '')
        
        seconds = calculate_seconds(duration, unit)
        expires = time.time() + seconds
        
        # Generar clave aleatoria
        import secrets
        key = secrets.token_hex(16)
        
        keys[key] = {
            'created': time.time(),
            'expires': expires,
            'duration': f"{duration} {unit}",
            'created_by': client_ip,
            'notes': notes,
            'status': 'active'
            # 'used_ip' se agregará automáticamente en el primer uso
        }
        
        # Log a Discord
        send_to_discord(
            "🔑 Nueva Clave Generada",
            f"**Clave:** `{key}`\n**Duración:** {duration} {unit}\n**Expira:** <t:{int(expires)}:F>\n**Creada por:** `{client_ip}`\n**Notas:** {notes}",
            0x6a0dad
        )
        
        return render_template_string(f"""
            {STYLES}
            <div class="container">
                <h1>🔑 Generar Clave</h1>
                <div class="alert alert-success">
                    <p>✅ Clave generada exitosamente!</p>
                </div>
                
                <div class="key-display">
                    {key}
                </div>
                
                <div class="key-info">
                    <p><strong>⏳ Duración:</strong> {duration} {unit}</p>
                    <p><strong>📅 Expira:</strong> {datetime.fromtimestamp(expires).strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <a href="{url_for('generate_key')}" style="display: block; text-align: center; margin-top: 20px;">
                    <button>🔑 Generar Otra Clave</button>
                </a>
                
                <div class="nav">
                    <a href="{url_for('index')}">🏠 Inicio</a>
                    <a href="{url_for('manage_keys')}">🗝️ Gestionar Claves</a>
                </div>
            </div>
        """)
    
    return render_template_string(f"""
        {STYLES}
        <div class="container">
            <h1>🔑 Generar Clave</h1>
            <form method="post">
                <div class="form-group">
                    <label for="duration">⏳ Duración</label>
                    <input type="number" id="duration" name="duration" min="1" value="1" required>
                </div>
                
                <div class="form-group">
                    <label for="unit">📅 Unidad de Tiempo</label>
                    <select id="unit" name="unit" required>
                        <option value="dia">Día</option>
                        <option value="dias" selected>Días</option>
                        <option value="semana">Semana</option>
                        <option value="semanas">Semanas</option>
                        <option value="mes">Mes</option>
                        <option value="meses">Meses</option>
                        <option value="año">Año</option>
                        <option value="años">Años</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="notes">📝 Notas (Opcional)</label>
                    <input type="text" id="notes" name="notes" placeholder="Ej: Clave para cliente X">
                </div>
                
                <button type="submit">✨ Generar Clave</button>
            </form>
            
            <div class="nav">
                <a href="{url_for('index')}">🏠 Inicio</a>
                <a href="{url_for('manage_keys')}">🗝️ Gestionar Claves</a>
            </div>
        </div>
    """)

@app.route('/manage-keys')
@login_required
def manage_keys():
    client_ip = get_client_ip()
    
    # Limpiar claves expiradas
    expired_keys = [k for k in keys if keys[k]['expires'] <= time.time()]
    for key in expired_keys:
        if keys[key]['status'] != 'expired':
            keys[key]['status'] = 'expired'
            send_to_discord(
                "⌛ Clave Expirada",
                f"**Clave:** `{key}`\n**Duración:** {keys[key]['duration']}\n**Creada por:** `{keys[key]['created_by']}`\n**Notas:** {keys[key]['notes']}",
                0xffa500
            )
    
    key_items = ""
    for key, data in keys.items():
        status = "🟢 Activa" if data['expires'] > time.time() else "🔴 Expirada"
        status_class = "badge-success" if data['expires'] > time.time() else "badge-danger"
        used_ip = data.get('used_ip', 'No activada aún')
        
        key_items += f"""
            <div class="key-item">
                <div class="key-info">
                    <div>
                        <strong>🔑 Clave:</strong> {key}<br>
                        <strong>🌐 IP Registrada:</strong> {used_ip}<br>
                        <strong>⏳ Duración:</strong> {data['duration']}<br>
                        <strong>📅 Creada:</strong> {datetime.fromtimestamp(data['created']).strftime('%Y-%m-%d %H:%M:%S')}
                    </div>
                    <div>
                        <span class="badge {status_class}">{status}</span>
                    </div>
                </div>
                <div class="key-info">
                    <div>
                        <strong>📅 Expira:</strong> {datetime.fromtimestamp(data['expires']).strftime('%Y-%m-%d %H:%M:%S')}<br>
                        <strong>👤 Creada por:</strong> {data['created_by']}<br>
                        <strong>📝 Notas:</strong> {data['notes']}
                    </div>
                </div>
                <div class="key-actions">
                    <form action="{url_for('delete_key', key=key)}" method="post" style="display: inline;">
                        <button type="submit" style="background-color: #ff0000;">🗑️ Eliminar</button>
                    </form>
                </div>
            </div>
        """
    
    return render_template_string(f"""
        {STYLES}
        <div class="container">
            <h1>🗝️ Gestionar Claves</h1>
            
            <div style="margin-bottom: 20px;">
                <form action="{url_for('validate_key')}" method="get" style="display: inline;">
                    <button type="submit" style="background-color: var(--secondary); color: var(--dark);">🔍 Validar Clave</button>
                </form>
            </div>
            
            <h3>🔑 Claves Activas ({len([k for k in keys if keys[k]['expires'] > time.time()])})</h3>
            {key_items if key_items else "<p>No hay claves activas.</p>"}
            
            <div class="nav">
                <a href="{url_for('index')}">🏠 Inicio</a>
                <a href="{url_for('generate_key')}">🔑 Generar Clave</a>
            </div>
        </div>
    """)


@app.route('/delete-key/<key>', methods=['POST'])
@login_required
def delete_key(key):
    client_ip = get_client_ip()
    
    if key in keys:
        deleted_key = keys.pop(key)
        
        send_to_discord(
            "🗑️ Clave Eliminada",
            f"**Clave:** `{key}`\n**Duración:** {deleted_key['duration']}\n**Eliminada por:** `{client_ip}`\n**Notas:** {deleted_key['notes']}\n**Estado previo:** {'Activa' if deleted_key['expires'] > time.time() else 'Expirada'}",
            0xff0000
        )
        
        return redirect(url_for('manage_keys'))
    
    return redirect(url_for('manage_keys'))

@app.route('/unban-ip', methods=['GET', 'POST'])
@login_required
def unban_ip():
    client_ip = get_client_ip()
    
    if request.method == 'POST':
        ip_to_unban = request.form.get('ip')
        
        if ip_to_unban in banned_ips:
            del banned_ips[ip_to_unban]
            
            send_to_discord(
                "🔓 IP Desbloqueada",
                f"**IP:** `{ip_to_unban}`\n**Desbloqueada por:** `{client_ip}`",
                0x00ff00
            )
            
            return render_template_string(f"""
                {STYLES}
                <div class="container">
                    <h1>🔓 Desbloquear IP</h1>
                    <div class="alert alert-success">
                        <p>✅ La IP {ip_to_unban} ha sido desbloqueada exitosamente.</p>
                    </div>
                    <a href="{url_for('unban_ip')}">
                        <button>↩️ Volver</button>
                    </a>
                </div>
            """)
        else:
            return render_template_string(f"""
                {STYLES}
                <div class="container">
                    <h1>🔓 Desbloquear IP</h1>
                    <div class="alert alert-danger">
                        <p>❌ La IP {ip_to_unban} no está bloqueada.</p>
                    </div>
                    <a href="{url_for('unban_ip')}">
                        <button>↩️ Volver</button>
                    </a>
                </div>
            """)
    
    banned_list = ""
    for ip, data in banned_ips.items():
        banned_list += f"""
            <tr>
                <td>{ip}</td>
                <td>{data['reason']}</td>
                <td>{datetime.fromtimestamp(data['until']).strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>
                    <form action="{url_for('unban_ip')}" method="post" style="display: inline;">
                        <input type="hidden" name="ip" value="{ip}">
                        <button type="submit" style="padding: 5px 10px;">🔓 Desbloquear</button>
                    </form>
                </td>
            </tr>
        """
    
    return render_template_string(f"""
        {STYLES}
        <div class="container">
            <h1>🔓 Desbloquear IP</h1>
            
            <h3>🚫 IPs Bloqueadas</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Razón</th>
                        <th>Bloqueada hasta</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    {banned_list if banned_list else "<tr><td colspan='4'>No hay IPs bloqueadas.</td></tr>"}
                </tbody>
            </table>
            
            <div class="nav">
                <a href="{url_for('index')}">🏠 Inicio</a>
                <a href="{url_for('generate_key')}">🔑 Generar Clave</a>
            </div>
        </div>
    """)

@app.route('/validatekey', methods=['GET'])
def validate_key():
    try:
        client_ip = get_client_ip()
        key = request.args.get('key')
        
        if not key:
            return jsonify({'status': 'error', 'message': 'Key requerida'}), 400
            
        # Validación real de la clave
        if key in keys:
            # Si es la primera vez que se usa la clave, registrar la IP
            if 'used_ip' not in keys[key]:
                keys[key]['used_ip'] = client_ip
                send_to_discord(
                    "🔐 Clave Activada",
                    f"**Clave:** `{key}`\n**IP Registrada:** `{client_ip}`\n**Notas:** {keys[key]['notes']}",
                    0x6a0dad
                )
            
            # Verificar si la IP coincide con la registrada
            elif keys[key]['used_ip'] != client_ip:
                # Registrar el intento no autorizado (pero NO eliminar la clave)
                send_to_discord(
                    "🚨 Intento de Uso No Autorizado",
                    f"**Clave:** `{key}`\n**IP Registrada:** `{keys[key]['used_ip']}`\n**IP Intento:** `{client_ip}`\n**Acción:** Acceso denegado (IP no coincide)",
                    0xff0000
                )
                
                return jsonify({
                    'status': 'error',
                    'message': 'Acceso denegado: IP no coincide con la registrada',
                    'valid': False,
                    'reason': 'invalid_ip'
                }), 403
                
            if keys[key]['expires'] > time.time():
                return jsonify({
                    'status': 'success',
                    'valid': True,
                    'expires': keys[key]['expires']
                })
            else:
                return jsonify({
                    'status': 'success',
                    'valid': False,
                    'reason': 'expired'
                })
        return jsonify({
            'status': 'success',
            'valid': False,
            'reason': 'not_found'
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Tarea para limpiar claves expiradas
def cleanup_expired_keys():
    while True:
        current_time = time.time()
        expired_keys = [k for k in keys if keys[k]['expires'] <= current_time]
        
        for key in expired_keys:
            if keys[key]['status'] != 'expired':
                keys[key]['status'] = 'expired'
                send_to_discord(
                    "⌛ Clave Expirada Automáticamente",
                    f"**Clave:** `{key}`\n**Duración:** {keys[key]['duration']}\n**Creada por:** `{keys[key]['created_by']}`\n**Notas:** {keys[key]['notes']}",
                    0xffa500
                )
        
        time.sleep(3600)  # Revisar cada hora

# Iniciar hilo de limpieza
import threading
cleanup_thread = threading.Thread(target=cleanup_expired_keys)
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
