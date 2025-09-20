const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const app = express();
const PORT = 8080;

// Configuración
const ADMIN_USERNAME = "admin123";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync("admin123", 10);
const WEBHOOK_URL = "https://discord.com/api/webhooks/1395449191068729364/-KuZXZT_lKgSNSnfMugtY5wJUdQxaq7GwQIG7QgRD_UODwpBy6_Nz7XrULCaSVasktsT";
const IP_ACCESS = "85.58.161.187";
const BAN_TIME = 60 * 60 * 24 * 60; // 2 meses en segundos
const MAX_LOGIN_ATTEMPTS = 2;

// Almacenamiento en memoria (en producción usarías una base de datos)
let keys = {};
let bannedIps = {};
let loginAttempts = {};
let activeSessions = {};

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'supersecretkey123!',
    resave: false,
    saveUninitialized: false
}));

// Estilos CSS (igual que en Python)
const STYLES = `
<style>
    /* Tus estilos CSS aquí (igual que en el código Python) */
</style>
`;

// Funciones de utilidad
function getClientIp(req) {
    const ipHeaders = [
        'X-Forwarded-For',
        'X-Real-IP',
        'CF-Connecting-IP',
        'True-Client-IP',
        'Forwarded',
        'Proxy-Client-IP',
        'WL-Proxy-Client-IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR'
    ];
    
    for (const header of ipHeaders) {
        if (req.headers[header.toLowerCase()]) {
            const ips = req.headers[header.toLowerCase()].split(',');
            const ip = ips[0].trim();
            if (ip) return ip;
        }
    }
    
    return req.ip || req.connection.remoteAddress;
}

async function getPublicIp() {
    try {
        const response = await axios.get('https://api.ipify.org?format=json', { timeout: 3000 });
        return response.data.ip;
    } catch (error) {
        try {
            const response = await axios.get('https://ipinfo.io/json', { timeout: 3000 });
            return response.data.ip;
        } catch (error) {
            return 'Desconocida';
        }
    }
}

function isBanned(ip) {
    if (bannedIps[ip] && bannedIps[ip].until > Date.now() / 1000) {
        return true;
    } else if (bannedIps[ip]) {
        delete bannedIps[ip];
    }
    return false;
}

async function sendToDiscord(title, description, color = 0x6a0dad) {
    const data = {
        embeds: [{
            title: `🔹 ${title}`,
            description: description,
            color: color,
            timestamp: new Date().toISOString(),
            footer: {
                text: "Key Management System"
            }
        }]
    };
    
    try {
        await axios.post(WEBHOOK_URL, data);
    } catch (error) {
        console.error("Error enviando a Discord:", error.message);
    }
}

function loginRequired(req, res, next) {
    const clientIp = getClientIp(req);
    
    if (isBanned(clientIp)) {
        return res.status(403).send(`
            ${STYLES}
            <div class="container">
                <h1>🔒 Acceso Bloqueado</h1>
                <div class="alert alert-danger">
                    <p>🚫 Tu IP (${clientIp}) ha sido bloqueada por intentos fallidos de inicio de sesión.</p>
                    <p>⏳ El bloqueo expirará en 2 meses.</p>
                </div>
            </div>
        `);
    }
    
    if (!activeSessions[clientIp] || activeSessions[clientIp].expires < Date.now() / 1000) {
        return res.redirect('/login');
    }
    
    next();
}

function calculateSeconds(amount, unit) {
    unit = unit.toLowerCase();
    if (['dia', 'dias'].includes(unit)) return amount * 86400;
    if (['semana', 'semanas'].includes(unit)) return amount * 604800;
    if (['mes', 'meses'].includes(unit)) return amount * 2592000; // 30 días
    if (['año', 'años'].includes(unit)) return amount * 31536000; // 365 días
    return amount;
}

// Rutas de la aplicación
app.get('/', loginRequired, async (req, res) => {
    const clientIp = getClientIp(req);
    const publicIp = await getPublicIp();
    
    const activeKeys = Object.values(keys).filter(k => k.expires > Date.now() / 1000).length;
    const expiredKeys = Object.values(keys).filter(k => k.expires <= Date.now() / 1000).length;
    
    res.send(`
        ${STYLES}
        <div class="container">
            <h1>🔑 Sistema de Gestión de Claves</h1>
            <div class="alert alert-success">
                <p>👋 Bienvenido, administrador!</p>
                <p>🖥️ Tu IP: ${publicIp} </p>
            </div>
            
            <div class="nav">
                <a href="/generate-key" class="active">🔑 Generar Clave</a>
                <a href="/manage-keys">🗝️ Gestionar Claves</a>
                <a href="/unban-ip">🔓 Desbloquear IP</a>
            </div>
            
            <h3>📊 Estadísticas</h3>
            <p>🔑 Claves activas: ${activeKeys}</p>
            <p>⏳ Claves expiradas: ${expiredKeys}</p>
            <p>🚫 IPs bloqueadas: ${Object.keys(bannedIps).length}</p>
            
            <form action="/logout" method="post" style="margin-top: 30px;">
                <button type="submit">🔒 Cerrar Sesión</button>
            </form>
        </div>
    `);
});

app.route('/login')
    .get((req, res) => {
        const clientIp = getClientIp(req);
        
        if (isBanned(clientIp)) {
            return res.status(403).send(`
                ${STYLES}
                <div class="container">
                    <h1>🔒 Acceso Bloqueado</h1>
                    <div class="alert alert-danger">
                        <p>🚫 Tu IP (${clientIp}) ha sido bloqueada por intentos fallidos de inicio de sesión.</p>
                        <p>⏳ El bloqueo expirará en 2 meses.</p>
                    </div>
                </div>
            `);
        }
        
        res.send(`
            ${STYLES}
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
        `);
    })
    .post(async (req, res) => {
        const clientIp = getClientIp(req);
        const { username, password } = req.body;
        
        if (isBanned(clientIp)) {
            return res.status(403).send(`
                ${STYLES}
                <div class="container">
                    <h1>🔒 Acceso Bloqueado</h1>
                    <div class="alert alert-danger">
                        <p>🚫 Tu IP (${clientIp}) ha sido bloqueada por intentos fallidos de inicio de sesión.</p>
                        <p>⏳ El bloqueo expirará en 2 meses.</p>
                    </div>
                </div>
            `);
        }
        
        if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
            // Resetear intentos fallidos
            delete loginAttempts[clientIp];
            
            // Crear sesión
            activeSessions[clientIp] = {
                loggedIn: true,
                expires: Date.now() / 1000 + 3600 // 1 hora de sesión
            };
            
            // Log a Discord
            await sendToDiscord(
                "✅ Inicio de Sesión Exitoso",
                `**IP:** \`${clientIp}\`\n**Usuario:** \`${username}\`\n**Hora:** ${new Date().toLocaleString('es-ES')}`,
                0x00ff00
            );
            
            return res.redirect('/');
        } else {
            // Registrar intento fallido
            if (!loginAttempts[clientIp]) loginAttempts[clientIp] = 0;
            loginAttempts[clientIp]++;
            
            // Bloquear IP si supera los intentos
            if (loginAttempts[clientIp] >= MAX_LOGIN_ATTEMPTS) {
                bannedIps[clientIp] = {
                    reason: 'Demasiados intentos de inicio de sesión fallidos',
                    until: Date.now() / 1000 + BAN_TIME
                };
                
                await sendToDiscord(
                    "🚫 IP Bloqueada",
                    `**IP:** \`${clientIp}\`\n**Razón:** Demasiados intentos de inicio de sesión fallidos\n**Bloqueo hasta:** ${new Date(Date.now() + BAN_TIME * 1000).toLocaleString('es-ES')}`,
                    0xff0000
                );
                
                return res.status(403).send(`
                    ${STYLES}
                    <div class="container">
                        <h1>🔒 Acceso Bloqueado</h1>
                        <div class="alert alert-danger">
                            <p>🚫 Demasiados intentos fallidos. Tu IP (${clientIp}) ha sido bloqueada por 2 meses.</p>
                        </div>
                    </div>
                `);
            }
            
            // Log a Discord
            await sendToDiscord(
                "⚠️ Intento de Inicio de Sesión Fallido",
                `**IP:** \`${clientIp}\`\n**Usuario:** \`${username}\`\n**Intento:** ${loginAttempts[clientIp]}/${MAX_LOGIN_ATTEMPTS}\n**Hora:** ${new Date().toLocaleString('es-ES')}`,
                0xffa500
            );
            
            return res.send(`
                ${STYLES}
                <div class="container">
                    <h1>🔑 Iniciar Sesión</h1>
                    <div class="alert alert-danger">
                        <p>❌ Usuario o contraseña incorrectos. Intentos restantes: ${MAX_LOGIN_ATTEMPTS - loginAttempts[clientIp]}</p>
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
            `);
        }
    });

app.post('/logout', loginRequired, async (req, res) => {
    const clientIp = getClientIp(req);
    delete activeSessions[clientIp];
    
    await sendToDiscord(
        "🔐 Sesión Cerrada",
        `**IP:** \`${clientIp}\`\n**Usuario:** \`${ADMIN_USERNAME}\`\n**Hora:** ${new Date().toLocaleString('es-ES')}`,
        0x6a0dad
    );
    
    res.redirect('/login');
});

app.route('/generate-key')
    .get(loginRequired, (req, res) => {
        res.send(`
            ${STYLES}
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
                    <a href="/">🏠 Inicio</a>
                    <a href="/manage-keys">🗝️ Gestionar Claves</a>
                </div>
            </div>
        `);
    })
    .post(loginRequired, async (req, res) => {
        const clientIp = getClientIp(req);
        const { duration, unit, notes } = req.body;
        
        const seconds = calculateSeconds(parseInt(duration), unit);
        const expires = Date.now() / 1000 + seconds;
        
        // Generar clave aleatoria
        const key = crypto.randomBytes(16).toString('hex');
        
        keys[key] = {
            created: Date.now() / 1000,
            expires: expires,
            duration: `${duration} ${unit}`,
            createdBy: clientIp,
            notes: notes || '',
            status: 'active'
        };
        
        // Log a Discord
        await sendToDiscord(
            "🔑 Nueva Clave Generada",
            `**Clave:** \`${key}\`\n**Duración:** ${duration} ${unit}\n**Expira:** ${new Date(expires * 1000).toLocaleString('es-ES')}\n**Creada por:** \`${clientIp}\`\n**Notas:** ${notes || 'Ninguna'}`,
            0x6a0dad
        );
        
        res.send(`
            ${STYLES}
            <div class="container">
                <h1>🔑 Generar Clave</h1>
                <div class="alert alert-success">
                    <p>✅ Clave generada exitosamente!</p>
                </div>
                
                <div class="key-display">
                    ${key}
                </div>
                
                <div class="key-info">
                    <p><strong>⏳ Duración:</strong> ${duration} ${unit}</p>
                    <p><strong>📅 Expira:</strong> ${new Date(expires * 1000).toLocaleString('es-ES')}</p>
                </div>
                
                <a href="/generate-key" style="display: block; text-align: center; margin-top: 20px;">
                    <button>🔑 Generar Otra Clave</button>
                </a>
                
                <div class="nav">
                    <a href="/">🏠 Inicio</a>
                    <a href="/manage-keys">🗝️ Gestionar Claves</a>
                </div>
            </div>
        `);
    });

app.get('/manage-keys', loginRequired, async (req, res) => {
    const clientIp = getClientIp(req);
    
    // Limpiar claves expiradas
    const expiredKeys = Object.keys(keys).filter(k => keys[k].expires <= Date.now() / 1000);
    for (const key of expiredKeys) {
        if (keys[key].status !== 'expired') {
            keys[key].status = 'expired';
            await sendToDiscord(
                "⌛ Clave Expirada",
                `**Clave:** \`${key}\`\n**Duración:** ${keys[key].duration}\n**Creada por:** \`${keys[key].createdBy}\`\n**Notas:** ${keys[key].notes}`,
                0xffa500
            );
        }
    }
    
    let keyItems = "";
    for (const [key, data] of Object.entries(keys)) {
        const isActive = data.expires > Date.now() / 1000;
        const status = isActive ? "🟢 Activa" : "🔴 Expirada";
        const statusClass = isActive ? "badge-success" : "badge-danger";
        const usedIp = data.usedIp || 'No activada aún';
        
        keyItems += `
            <div class="key-item">
                <div class="key-info">
                    <div>
                        <strong>🔑 Clave:</strong> ${key}<br>
                        <strong>🌐 IP Registrada:</strong> ${usedIp}<br>
                        <strong>⏳ Duración:</strong> ${data.duration}<br>
                        <strong>📅 Creada:</strong> ${new Date(data.created * 1000).toLocaleString('es-ES')}
                    </div>
                    <div>
                        <span class="badge ${statusClass}">${status}</span>
                    </div>
                </div>
                <div class="key-info">
                    <div>
                        <strong>📅 Expira:</strong> ${new Date(data.expires * 1000).toLocaleString('es-ES')}<br>
                        <strong>👤 Creada por:</strong> ${data.createdBy}<br>
                        <strong>📝 Notas:</strong> ${data.notes}
                    </div>
                </div>
                <div class="key-actions">
                    <form action="/delete-key/${key}" method="post" style="display: inline;">
                        <button type="submit" style="background-color: #ff0000;">🗑️ Eliminar</button>
                    </form>
                </div>
            </div>
        `;
    }
    
    const activeKeysCount = Object.values(keys).filter(k => k.expires > Date.now() / 1000).length;
    
    res.send(`
        ${STYLES}
        <div class="container">
            <h1>🗝️ Gestionar Claves</h1>
            
            <div style="margin-bottom: 20px;">
                <form action="/validatekey" method="get" style="display: inline;">
                    <button type="submit" style="background-color: var(--secondary); color: var(--dark);">🔍 Validar Clave</button>
                </form>
            </div>
            
            <h3>🔑 Claves Activas (${activeKeysCount})</h3>
            ${keyItems || "<p>No hay claves activas.</p>"}
            
            <div class="nav">
                <a href="/">🏠 Inicio</a>
                <a href="/generate-key">🔑 Generar Clave</a>
            </div>
        </div>
    `);
});

app.post('/delete-key/:key', loginRequired, async (req, res) => {
    const clientIp = getClientIp(req);
    const { key } = req.params;
    
    if (keys[key]) {
        const deletedKey = keys[key];
        delete keys[key];
        
        await sendToDiscord(
            "🗑️ Clave Eliminada",
            `**Clave:** \`${key}\`\n**Duración:** ${deletedKey.duration}\n**Eliminada por:** \`${clientIp}\`\n**Notas:** ${deletedKey.notes}\n**Estado previo:** ${deletedKey.expires > Date.now() / 1000 ? 'Activa' : 'Expirada'}`,
            0xff0000
        );
    }
    
    res.redirect('/manage-keys');
});

app.route('/unban-ip')
    .get(loginRequired, (req, res) => {
        let bannedList = "";
        for (const [ip, data] of Object.entries(bannedIps)) {
            bannedList += `
                <tr>
                    <td>${ip}</td>
                    <td>${data.reason}</td>
                    <td>${new Date(data.until * 1000).toLocaleString('es-ES')}</td>
                    <td>
                        <form action="/unban-ip" method="post" style="display: inline;">
                            <input type="hidden" name="ip" value="${ip}">
                            <button type="submit" style="padding: 5px 10px;">🔓 Desbloquear</button>
                        </form>
                    </td>
                </tr>
            `;
        }
        
        res.send(`
            ${STYLES}
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
                        ${bannedList || "<tr><td colspan='4'>No hay IPs bloqueadas.</td></tr>"}
                    </tbody>
                </table>
                
                <div class="nav">
                    <a href="/">🏠 Inicio</a>
                    <a href="/generate-key">🔑 Generar Clave</a>
                </div>
            </div>
        `);
    })
    .post(loginRequired, async (req, res) => {
        const clientIp = getClientIp(req);
        const { ip } = req.body;
        
        if (bannedIps[ip]) {
            delete bannedIps[ip];
            
            await sendToDiscord(
                "🔓 IP Desbloqueada",
                `**IP:** \`${ip}\`\n**Desbloqueada por:** \`${clientIp}\``,
                0x00ff00
            );
            
            res.send(`
                ${STYLES}
                <div class="container">
                    <h1>🔓 Desbloquear IP</h1>
                    <div class="alert alert-success">
                        <p>✅ La IP ${ip} ha sido desbloqueada exitosamente.</p>
                    </div>
                    <a href="/unban-ip">
                        <button>↩️ Volver</button>
                    </a>
                </div>
            `);
        } else {
            res.send(`
                ${STYLES}
                <div class="container">
                    <h1>🔓 Desbloquear IP</h1>
                    <div class="alert alert-danger">
                        <p>❌ La IP ${ip} no está bloqueada.</p>
                    </div>
                    <a href="/unban-ip">
                        <button>↩️ Volver</button>
                    </a>
                </div>
            `);
        }
    });

app.get('/validatekey', async (req, res) => {
    try {
        const clientIp = getClientIp(req);
        const { key } = req.query;
        
        if (!key) {
            return res.status(400).json({ status: 'error', message: 'Key requerida' });
        }
        
        // Validación real de la clave
        if (keys[key]) {
            // Si es la primera vez que se usa la clave, registrar la IP
            if (!keys[key].usedIp) {
                keys[key].usedIp = clientIp;
                await sendToDiscord(
                    "🔐 Clave Activada",
                    `**Clave:** \`${key}\`\n**IP Registrada:** \`${clientIp}\`\n**Notas:** ${keys[key].notes}`,
                    0x6a0dad
                );
            }
            
            // Verificar si la IP coincide con la registrada
            else if (keys[key].usedIp !== clientIp) {
                // Registrar el intento no autorizado
                await sendToDiscord(
                    "🚨 Intento de Uso No Autorizado",
                    `**Clave:** \`${key}\`\n**IP Registrada:** \`${keys[key].usedIp}\`\n**IP Intento:** \`${clientIp}\`\n**Acción:** Acceso denegado (IP no coincide)`,
                    0xff0000
                );
                
                return res.status(403).json({
                    status: 'error',
                    message: 'Acceso denegado: IP no coincide con la registrada',
                    valid: false,
                    reason: 'invalid_ip'
                });
            }
            
            if (keys[key].expires > Date.now() / 1000) {
                return res.json({
                    status: 'success',
                    valid: true,
                    expires: keys[key].expires
                });
            } else {
                return res.json({
                    status: 'success',
                    valid: false,
                    reason: 'expired'
                });
            }
        }
        
        return res.json({
            status: 'success',
            valid: false,
            reason: 'not_found'
        });
        
    } catch (error) {
        return res.status(500).json({ status: 'error', message: error.message });
    }
});

// Tarea para limpiar claves expiradas
setInterval(() => {
    const currentTime = Date.now() / 1000;
    const expiredKeys = Object.keys(keys).filter(k => keys[k].expires <= currentTime);
    
    expiredKeys.forEach(async (key) => {
        if (keys[key].status !== 'expired') {
            keys[key].status = 'expired';
            await sendToDiscord(
                "⌛ Clave Expirada Automáticamente",
                `**Clave:** \`${key}\`\n**Duración:** ${keys[key].duration}\n**Creada por:** \`${keys[key].createdBy}\`\n**Notas:** ${keys[key].notes}`,
                0xffa500
            );
        }
    });
}, 3600000); // Revisar cada hora

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor ejecutándose en http://0.0.0.0:${PORT}`);
});
