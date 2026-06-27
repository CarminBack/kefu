const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');

// --- Telegram Configuration ---
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID;

if (!TELEGRAM_TOKEN || !ADMIN_CHAT_ID) {
    throw new Error('TELEGRAM_TOKEN and ADMIN_CHAT_ID environment variables are required.');
}

const bot = new TelegramBot(TELEGRAM_TOKEN, { polling: true });

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const IMAGE_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const IMAGE_TYPES = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp'
};
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error('ADMIN_USERNAME and ADMIN_PASSWORD environment variables are required.');
}
const ADMIN_COOKIE = 'support_admin_session';
const ADMIN_SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const adminSessions = new Map();

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
cleanupExpiredUploads();
setInterval(cleanupExpiredUploads, 6 * 60 * 60 * 1000);

// Initialize SQLite Database
const dbPath = path.join(DATA_DIR, 'chat.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error opening database', err);
    else {
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            tg_message_id TEXT,
            is_read INTEGER DEFAULT 0
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS conversation_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret TEXT NOT NULL UNIQUE,
            conversation_id TEXT NOT NULL UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            used_at DATETIME,
            revoked INTEGER DEFAULT 0
        )`);
    }
});

// Store connected clients: email -> Set<WebSocket>
const clients = new Map();
// Store complete websocket connection metadata temporarily if needed
const activeConnections = new Set();
const admins = new Set(); // Browser admins if any

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/support/uploads', express.static(UPLOAD_DIR));
app.use(express.json());
app.use('/api/upload', express.raw({ type: Object.keys(IMAGE_TYPES), limit: `${MAX_IMAGE_BYTES}b` }));
app.use('/support/api/upload', express.raw({ type: Object.keys(IMAGE_TYPES), limit: `${MAX_IMAGE_BYTES}b` }));
app.use('/api/admin/upload', express.raw({ type: Object.keys(IMAGE_TYPES), limit: `${MAX_IMAGE_BYTES}b` }));
app.use('/support/api/admin/upload', express.raw({ type: Object.keys(IMAGE_TYPES), limit: `${MAX_IMAGE_BYTES}b` }));

function parseCookies(req) {
    return String(req.headers.cookie || '')
        .split(';')
        .map(item => item.trim())
        .filter(Boolean)
        .reduce((cookies, item) => {
            const index = item.indexOf('=');
            if (index === -1) return cookies;
            cookies[decodeURIComponent(item.slice(0, index))] = decodeURIComponent(item.slice(index + 1));
            return cookies;
        }, {});
}

function secureCookieSuffix(req) {
    return req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted ? '; Secure' : '';
}

function adminCookie(req, token) {
    return `${ADMIN_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(ADMIN_SESSION_TTL_MS / 1000)}${secureCookieSuffix(req)}`;
}

function clearAdminCookie(req) {
    return `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureCookieSuffix(req)}`;
}

function cleanupAdminSessions() {
    const now = Date.now();
    for (const [token, session] of adminSessions.entries()) {
        if (!session || session.expiresAt <= now) adminSessions.delete(token);
    }
}

function getAdminSession(req) {
    cleanupAdminSessions();
    const token = parseCookies(req)[ADMIN_COOKIE];
    if (!token) return null;
    const session = adminSessions.get(token);
    if (!session || session.expiresAt <= Date.now()) {
        adminSessions.delete(token);
        return null;
    }
    return { token, session };
}

function requireAdmin(req, res) {
    if (getAdminSession(req)) return true;
    res.status(401).json({ error: '请先登录客服后台' });
    return false;
}

function safeEqual(left, right) {
    const leftBuffer = Buffer.from(String(left));
    const rightBuffer = Buffer.from(String(right));
    return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function normalizeSecret(secret = '') {
    return String(secret).trim().replace(/\s+/g, '').toUpperCase();
}

function createConversationSecret() {
    return crypto.randomBytes(9).toString('base64url').toUpperCase();
}

function createConversationId() {
    return `会话-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
}

function validateConversationKey(secret, callback) {
    const normalized = normalizeSecret(secret);
    if (!normalized) return callback(null, null);
    db.get(
        `SELECT secret, conversation_id FROM conversation_keys WHERE secret = ? AND revoked = 0`,
        [normalized],
        (err, row) => {
            if (err) return callback(err);
            if (!row) return callback(null, null);
            db.run(`UPDATE conversation_keys SET used_at = COALESCE(used_at, CURRENT_TIMESTAMP) WHERE secret = ?`, [normalized]);
            callback(null, row);
        }
    );
}

app.post(['/api/admin/login', '/support/api/admin/login'], (req, res) => {
    const { username = '', password = '' } = req.body || {};
    if (!safeEqual(username, ADMIN_USERNAME) || !safeEqual(password, ADMIN_PASSWORD)) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    const token = crypto.randomBytes(32).toString('base64url');
    adminSessions.set(token, { username: ADMIN_USERNAME, expiresAt: Date.now() + ADMIN_SESSION_TTL_MS });
    res.setHeader('Set-Cookie', adminCookie(req, token));
    res.json({ ok: true, username: ADMIN_USERNAME });
});

app.post(['/api/admin/logout', '/support/api/admin/logout'], (req, res) => {
    const session = getAdminSession(req);
    if (session) adminSessions.delete(session.token);
    res.setHeader('Set-Cookie', clearAdminCookie(req));
    res.json({ ok: true });
});

app.get(['/api/admin/me', '/support/api/admin/me'], (req, res) => {
    const session = getAdminSession(req);
    if (!session) return res.status(401).json({ error: '请先登录客服后台' });
    res.json({ ok: true, username: session.session.username });
});

app.post(['/api/admin/conversation-key', '/support/api/admin/conversation-key'], (req, res) => {
    if (!requireAdmin(req, res)) return;

    const secret = createConversationSecret();
    const conversationId = createConversationId();
    db.run(
        `INSERT INTO conversation_keys (secret, conversation_id) VALUES (?, ?)`,
        [secret, conversationId],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
            const host = req.headers.host || 'kefu.mewinyou.shop';
            res.json({
                ok: true,
                secret,
                conversation_id: conversationId,
                url: `${proto}://${host}/?key=${encodeURIComponent(secret)}`
            });
        }
    );
});

app.post(['/api/conversation-key/verify', '/support/api/conversation-key/verify'], (req, res) => {
    validateConversationKey(req.body && req.body.secret, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(401).json({ error: '对话秘钥无效' });
        res.json({ ok: true, conversation_id: row.conversation_id, secret: row.secret });
    });
});

// API: Get history
function historyHandler(req, res, options = {}) {
    const { email } = req.query;
    if (!email) return res.status(400).send('Email required');
    if (options.requireKey) {
        validateConversationKey(req.query.key, (keyErr, row) => {
            if (keyErr) return res.status(500).json({ error: keyErr.message });
            if (!row || row.conversation_id !== email) return res.status(401).json({ error: '对话秘钥无效' });
            return historyHandler(req, res, { ...options, requireKey: false });
        });
        return;
    }
    db.all(`SELECT sender, content, timestamp FROM messages WHERE email = ? ORDER BY timestamp ASC`, [email], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        if (options.markUserMessagesRead) {
            db.run(`UPDATE messages SET is_read = 1 WHERE email = ? AND sender = 'user'`, [email]);
        }
        res.json(rows);
    });
}

app.get('/api/history', (req, res) => historyHandler(req, res, { requireKey: true }));
app.get('/support/api/history', (req, res) => historyHandler(req, res, { requireKey: true }));

// API: Get users
function usersHandler(req, res) {
    db.all(`
        SELECT
            m.email,
            MAX(m.timestamp) AS last_active,
            (
                SELECT m2.content FROM messages m2
                WHERE m2.email = m.email
                ORDER BY m2.timestamp DESC, m2.id DESC
                LIMIT 1
            ) AS latest_content,
            (
                SELECT m2.sender FROM messages m2
                WHERE m2.email = m.email
                ORDER BY m2.timestamp DESC, m2.id DESC
                LIMIT 1
            ) AS latest_sender,
            (
                SELECT COUNT(*) FROM messages unread
                WHERE unread.email = m.email AND unread.sender = 'user' AND IFNULL(unread.is_read, 0) = 0
            ) AS unread_count,
            (
                SELECT admin_msg.is_read FROM messages admin_msg
                WHERE admin_msg.email = m.email AND admin_msg.sender = 'admin'
                ORDER BY admin_msg.timestamp DESC, admin_msg.id DESC
                LIMIT 1
            ) AS customer_read
        FROM messages m
        GROUP BY m.email
        ORDER BY last_active DESC
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows.map(row => ({
            ...row,
            unread_count: Number(row.unread_count || 0),
            customer_read: row.customer_read === null || row.customer_read === undefined ? null : Boolean(row.customer_read)
        })));
    });
}

app.get('/api/users', (req, res) => {
    if (!requireAdmin(req, res)) return;
    usersHandler(req, res);
});
app.get('/support/api/users', (req, res) => {
    if (!requireAdmin(req, res)) return;
    usersHandler(req, res);
});

app.get(['/api/admin/users', '/support/api/admin/users'], (req, res) => {
    if (!requireAdmin(req, res)) return;
    usersHandler(req, res);
});

app.get(['/api/admin/history', '/support/api/admin/history'], (req, res) => {
    if (!requireAdmin(req, res)) return;
    historyHandler(req, res, { markUserMessagesRead: true });
});

app.post(['/api/admin/conversation/read', '/support/api/admin/conversation/read'], (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });

    db.run(`UPDATE messages SET is_read = 1 WHERE email = ? AND sender = 'user'`, [email], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ ok: true, updated: this.changes || 0 });
    });
});

app.delete(['/api/admin/conversation', '/support/api/admin/conversation'], (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email required' });

    db.run(`DELETE FROM messages WHERE email = ?`, [email], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ ok: true, deleted: this.changes || 0 });
    });
});

function uploadHandler(req, res) {
    const mimeType = String(req.headers['content-type'] || '').split(';')[0].toLowerCase();
    const ext = IMAGE_TYPES[mimeType];

    if (!ext) return res.status(415).json({ error: 'Only jpg, png, gif, and webp images are supported.' });
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) return res.status(400).json({ error: 'Image data required.' });

    const fileName = `${Date.now()}-${Math.random().toString(16).slice(2)}.${ext}`;
    const filePath = path.join(UPLOAD_DIR, fileName);

    fs.writeFile(filePath, req.body, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        cleanupExpiredUploads();
        res.json({
            type: 'image',
            url: `/uploads/${fileName}`,
            name: String(req.headers['x-file-name'] || 'image').slice(0, 120),
            mimeType,
            size: req.body.length
        });
    });
}

function customerUploadHandler(req, res) {
    const secret = req.headers['x-conversation-secret'] || req.query.key;
    validateConversationKey(secret, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(401).json({ error: '对话秘钥无效' });
        uploadHandler(req, res);
    });
}

app.post('/api/upload', customerUploadHandler);
app.post('/support/api/upload', customerUploadHandler);
app.post(['/api/admin/upload', '/support/api/admin/upload'], (req, res) => {
    if (!requireAdmin(req, res)) return;
    uploadHandler(req, res);
});

function parseMessageContent(content) {
    try {
        const parsed = JSON.parse(content);
        if (parsed && parsed.type === 'image' && typeof parsed.url === 'string') return parsed;
    } catch {}
    return { type: 'text', text: String(content || '') };
}

function summarizeContent(content) {
    const parsed = parseMessageContent(content);
    if (parsed.type === 'image') return '[图片]';
    return parsed.text || '';
}

function publicUrl(req, url) {
    const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
    const host = req.headers.host || 'kefu.mewinyou.shop';
    return `${proto}://${host}${url}`;
}

function downloadTelegramPhoto(fileUrl) {
    return new Promise((resolve, reject) => {
        https.get(fileUrl, (response) => {
            if (response.statusCode !== 200) {
                response.resume();
                reject(new Error(`Telegram file download failed: ${response.statusCode}`));
                return;
            }

            const contentType = String(response.headers['content-type'] || '').split(';')[0].toLowerCase();
            const ext = IMAGE_TYPES[contentType] || 'jpg';
            const chunks = [];
            let total = 0;

            response.on('data', (chunk) => {
                total += chunk.length;
                if (total > MAX_IMAGE_BYTES) {
                    response.destroy(new Error('Telegram image is too large.'));
                    return;
                }
                chunks.push(chunk);
            });

            response.on('end', () => {
                const fileName = `${Date.now()}-${Math.random().toString(16).slice(2)}.${ext}`;
                fs.writeFile(path.join(UPLOAD_DIR, fileName), Buffer.concat(chunks), (err) => {
                    if (err) return reject(err);
                    cleanupExpiredUploads();
                    resolve(`/uploads/${fileName}`);
                });
            });
        }).on('error', reject);
    });
}

function cleanupExpiredUploads() {
    fs.readdir(UPLOAD_DIR, (err, files) => {
        if (err) return;
        const now = Date.now();
        files.forEach(fileName => {
            const filePath = path.join(UPLOAD_DIR, fileName);
            fs.stat(filePath, (statErr, stat) => {
                if (statErr || !stat.isFile()) return;
                if (now - stat.mtimeMs > IMAGE_RETENTION_MS) {
                    fs.unlink(filePath, () => {});
                }
            });
        });
    });
}

// --- Function to Broadcast to the Web User ---
function sendToWebUser(email, sender, content) {
    const msgObj = JSON.stringify({
        type: 'message',
        email: email,
        sender: sender,
        content: content,
        timestamp: new Date().toISOString()
    });

    if (clients.has(email)) {
        clients.get(email).forEach(clientWs => {
            if (clientWs.readyState === WebSocket.OPEN) {
                clientWs.send(msgObj);
            }
        });
    }
    
    // Legacy support for web admin if still open
    admins.forEach(adminWs => {
        if (adminWs.readyState === WebSocket.OPEN) {
            adminWs.send(msgObj);
        }
    });
}

// --- WebSocket Logic ---
wss.on('connection', (ws, req) => {
    let currentEmail = null;
    let isAdmin = false;
    activeConnections.add(ws);

    ws.on('message', (message) => {
        const data = JSON.parse(message);

        if (data.type === 'auth') {
            if (data.role === 'admin') {
                if (!getAdminSession(req)) {
                    ws.send(JSON.stringify({ type: 'auth_error', message: '请先登录客服后台' }));
                    ws.close();
                    return;
                }
                isAdmin = true;
                admins.add(ws);
            } else if (data.role === 'user') {
                validateConversationKey(data.secret, (err, keyRow) => {
                    if (err || !keyRow) {
                        ws.send(JSON.stringify({ type: 'auth_error', message: '对话秘钥无效' }));
                        ws.close();
                        return;
                    }
                    currentEmail = keyRow.conversation_id;
                    ws.send(JSON.stringify({ type: 'auth_ok', email: currentEmail }));
                    if (!clients.has(currentEmail)) {
                        clients.set(currentEmail, new Set());
                    }
                    clients.get(currentEmail).add(ws);
                });
            }
        } 
        else if (data.type === 'message') {
            const content = data.content;
            const targetEmail = isAdmin ? data.targetEmail : currentEmail;
            const sender = isAdmin ? 'admin' : 'user';

            if (!targetEmail) return;

            // Broadcast visually first
            sendToWebUser(targetEmail, sender, content);

            // Forward to Telegram if the user sent it
            if (sender === 'user') {
                const parsedContent = parseMessageContent(content);
                db.run(`INSERT INTO messages (email, sender, content, is_read) VALUES (?, ?, ?, 0)`, [targetEmail, sender, content], function(err) {
                    if (err) return console.error(err);

                    const localMessageId = this.lastID;
                    const sendToTelegram = parsedContent.type === 'image'
                        ? bot.sendPhoto(ADMIN_CHAT_ID, publicUrl(req, parsedContent.url), { caption: `✉️ User: ${targetEmail}` })
                        : bot.sendMessage(ADMIN_CHAT_ID, `✉️ **User: ${targetEmail}**\n\n${content}`, { parse_mode: 'Markdown' });

                    sendToTelegram
                        .then((sentMsg) => {
                            db.run(`UPDATE messages SET tg_message_id = ? WHERE id = ?`, [sentMsg.message_id.toString(), localMessageId]);
                        })
                        .catch(err => console.error("Error sending to TG:", err));
                });
            } else {
                // If it came from the web admin (legacy)
                db.run(`INSERT INTO messages (email, sender, content, is_read) VALUES (?, ?, ?, 0)`, [targetEmail, 'admin', content], function(err) {
                    if (err) return console.error(err);
                });
            }
        } else if (data.type === 'read_receipt') {
            if (currentEmail) {
                db.run(`UPDATE messages SET is_read = 1 WHERE email = ? AND sender = 'admin'`, [currentEmail], () => {
                    admins.forEach(adminWs => {
                        if (adminWs.readyState === WebSocket.OPEN) {
                            adminWs.send(JSON.stringify({ type: 'customer_read', email: currentEmail }));
                        }
                    });
                });
            }
        }
    });

    ws.on('close', () => {
        activeConnections.delete(ws);
        if (isAdmin) {
            admins.delete(ws);
        } else if (currentEmail && clients.has(currentEmail)) {
            clients.get(currentEmail).delete(ws);
            if (clients.get(currentEmail).size === 0) {
                clients.delete(currentEmail);
            }
        }
    });
});

// --- Error Logging Setup ---
console.error = (...args) => {
    require('fs').appendFileSync(path.join(__dirname, 'error.log'), new Date().toISOString() + ': ' + args.join(' ') + '\n');
};

// --- Telegram Incoming Message Handler (You replying to user) ---
bot.on('message', (msg) => {
    if (msg.chat.id.toString() !== ADMIN_CHAT_ID) return;

    if (msg.reply_to_message) {
        const replyToId = msg.reply_to_message.message_id.toString();
        
        db.get(`SELECT email FROM messages WHERE tg_message_id = ?`, [replyToId], (err, row) => {
            if (err) return console.error(err);
            if (row && row.email) {
                const targetEmail = row.email;
                let adminReply = msg.text;
                if (msg.photo && msg.photo.length > 0) {
                    const largestPhoto = msg.photo[msg.photo.length - 1];
                    const caption = msg.caption || '';
                    bot.getFileLink(largestPhoto.file_id)
                        .then(downloadTelegramPhoto)
                        .then((localUrl) => {
                            const imageContent = JSON.stringify({
                                type: 'image',
                                url: localUrl,
                                name: caption || '客服图片'
                            });
                            saveAdminReply(targetEmail, imageContent);
                        })
                        .catch(err => console.error('Error getting TG photo:', err));
                    return;
                }
                if (!adminReply) return;

                saveAdminReply(targetEmail, adminReply);
            } else {
                bot.sendMessage(ADMIN_CHAT_ID, "⚠️ Could not find the associated user for that specific message.");
            }
        });
    } else {
        if (msg.text && !msg.text.startsWith('/')) {
             bot.sendMessage(ADMIN_CHAT_ID, "ℹ️ You must **Reply** to the user's specific forwarded message in here so I know which customer to send your text back to.");
        }
    }
});

function saveAdminReply(targetEmail, adminReply) {
    db.run(`INSERT INTO messages (email, sender, content, is_read) VALUES (?, ?, ?, 0)`, [targetEmail, 'admin', adminReply], function(err) {
        if (err) return console.error(err);

        sendToWebUser(targetEmail, 'admin', adminReply);
    });
}

// Basic start command just for the bot itself
bot.onText(/\/start/, (msg) => {
    bot.sendMessage(msg.chat.id, "🤖 Support Relay Bot is active. When a user sends a message on the website, it will appear here. Simply click/tap 'Reply' on their message to respond to them!");
});

const PORT = 19999;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
