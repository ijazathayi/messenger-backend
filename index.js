require('dotenv').config();

// Debug: log which env vars are present (values hidden for security)
console.log('[ENV CHECK] TURSO_DATABASE_URL:', process.env.TURSO_DATABASE_URL ? '✅ set' : '❌ missing');
console.log('[ENV CHECK] TURSO_AUTH_TOKEN:', process.env.TURSO_AUTH_TOKEN ? '✅ set' : '❌ missing');
console.log('[ENV CHECK] GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? '✅ set' : '❌ missing');

const express = require('express');
const cors    = require('cors');
const http    = require('http');
const { Server }       = require('socket.io');
const multer           = require('multer');
const path             = require('path');
const fs               = require('fs');
const jwt              = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const { v2: cloudinary } = require('cloudinary');
const streamifier        = require('streamifier');

// Initialize DB
const db = require('./db');

const JWT_SECRET = process.env.SESSION_SECRET || 'messenger_chat_secret';
const JWT_EXPIRY = '30d'; // stay logged in for 30 days

// Initialize DB
const db = require('./db');

// ── Cloudinary config ─────────────────────────────────────────────────────────
const USE_CLOUDINARY = !!(
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY    &&
  process.env.CLOUDINARY_API_SECRET
);

if (USE_CLOUDINARY) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key:    process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  console.log('[Upload] Using Cloudinary for file storage.');
} else {
  console.log('[Upload] Using local disk for file storage (dev mode).');
}

// ── Migration: assign 4-digit codes to users who don't have one yet ──
setTimeout(() => {
  db.all('SELECT id FROM users WHERE user_code IS NULL', [], (err, rows) => {
    if (err || !rows || rows.length === 0) return;
    console.log(`[Migration] Assigning user_code to ${rows.length} existing user(s)...`);
    function assignCode(i) {
      if (i >= rows.length) return;
      const userId = rows[i].id;
      function tryCode() {
        const code = String(Math.floor(1000 + Math.random() * 9000));
        db.get('SELECT id FROM users WHERE user_code = ?', [code], (err2, existing) => {
          if (err2 || existing) { tryCode(); return; }
          db.run('UPDATE users SET user_code = ? WHERE id = ?', [code, userId], () => {
            console.log(`[Migration] User #${userId} assigned code ${code}`);
            assignCode(i + 1);
          });
        });
      }
      tryCode();
    }
    assignCode(0);
  });
}, 1000);

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Accept both local and production origins from env
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5174';

const allowedOrigins = [
  FRONTEND_URL,
  'http://127.0.0.1:5174',
  'http://localhost:3002',
  'http://127.0.0.1:3002',
].filter(Boolean);

const app    = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io     = new Server(server, {
  cors: {
    origin:      allowedOrigins,
    methods:     ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  },
});

// ─── Multer (memory storage — works on cloud & local) ─────────────────────────
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

// ─── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) { callback(null, true); return; }
    const isAllowed =
      allowedOrigins.includes(origin) ||
      origin.startsWith('http://localhost:') ||
      origin.startsWith('http://127.0.0.1:');
    callback(null, true); // allow all for dev
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
}));

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ─── Auth Helpers ──────────────────────────────────────────────
async function verifyGoogleToken(idToken) {
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: GOOGLE_CLIENT_ID,
  });
  return ticket.getPayload();
}

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Unauthorized' });
      req.user = user;
      next();
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Generate a unique 4-digit code (1000–9999) not already taken
function generateUserCode(cb) {
  const code = String(Math.floor(1000 + Math.random() * 9000));
  db.get('SELECT id FROM users WHERE user_code = ?', [code], (err, row) => {
    if (err || row) {
      // collision or error – try again
      generateUserCode(cb);
    } else {
      cb(code);
    }
  });
}

// ─── Auth Routes ───────────────────────────────────────────────

app.post('/auth/google/token', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ error: 'ID token required' });

  try {
    const payload = await verifyGoogleToken(idToken);
    const { sub: googleId, email, name, picture } = payload;

    db.get('SELECT * FROM users WHERE google_id = ?', [googleId], (err, existingUser) => {
      if (err) return res.status(500).json({ error: err.message });

      if (existingUser) {
        db.run('UPDATE users SET avatar = ? WHERE id = ?', [picture, existingUser.id], () => {});
        const token = jwt.sign({ userId: existingUser.id }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
        return res.json({ success: true, token, user: { ...existingUser, avatar: picture } });
      }

      generateUserCode((userCode) => {
        db.run(
          'INSERT INTO users (google_id, name, email, avatar, user_code) VALUES (?, ?, ?, ?, ?)',
          [googleId, name, email, picture, userCode],
          function (err) {
            if (err) return res.status(500).json({ error: err.message });
            const newUser = { id: this.lastID, google_id: googleId, name, email, avatar: picture, user_code: userCode };
            const token = jwt.sign({ userId: this.lastID }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
            return res.json({ success: true, token, user: newUser });
          }
        );
      });
    });
  } catch (err) {
    console.error('[Auth] Token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid Google token' });
  }
});

app.get('/auth/status', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.json({ authenticated: false });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    db.get('SELECT * FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err || !user) return res.json({ authenticated: false });
      res.json({ authenticated: true, user });
    });
  } catch (e) {
    res.json({ authenticated: false });
  }
});

app.post('/auth/logout', (req, res) => {
  // JWT is stateless — client just deletes the token
  res.json({ success: true });
});

// ─── Admin Routes ──────────────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin123';

const adminAuth = (req, res, next) => {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (key !== ADMIN_KEY) {
    return res.status(403).json({ error: 'Forbidden: Invalid admin key' });
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized: No token' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    db.get('SELECT email FROM users WHERE id = ?', [decoded.userId], (err, user) => {
      if (err || !user) return res.status(401).json({ error: 'Unauthorized: User not found' });
      if (user.email !== 'theijazlegacy@gmail.com') {
        return res.status(403).json({ error: 'Forbidden: You do not have admin privileges' });
      }
      next();
    });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

app.get('/admin/stats', adminAuth, (req, res) => {
  db.get('SELECT COUNT(*) as total FROM users', (err, usersRow) => {
    if (err) return res.status(500).json({ error: err.message });
    db.get('SELECT COUNT(*) as total FROM messages WHERE is_deleted = 0', (err, msgRow) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({
        total_users: usersRow.total,
        total_messages: msgRow.total,
        online_users: userSockets.size,
        online_user_ids: Array.from(userSockets.keys())
      });
    });
  });
});

app.get('/admin/users', adminAuth, (req, res) => {
  db.all(`SELECT id, name, email, avatar, about, user_code, created_at,
      (SELECT COUNT(*) FROM messages WHERE sender_id = users.id OR receiver_id = users.id) as message_count
      FROM users ORDER BY created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const onlineIds = new Set(userSockets.keys());
    res.json(rows.map(u => ({ ...u, is_online: onlineIds.has(u.id) })));
  });
});

app.put('/admin/users/:id', adminAuth, (req, res) => {
  const userId = req.params.id;
  const { name, email, about, user_code } = req.body;

  // Basic validation for 4-digit code
  if (user_code && !/^\d{4}$/.test(user_code)) {
    return res.status(400).json({ error: 'User ID must be exactly a 4-digit number' });
  }

  // Check unique constraint for user_code if changed
  db.get('SELECT id FROM users WHERE user_code = ? AND id != ?', [user_code, userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row) return res.status(400).json({ error: 'This unique 4-digit ID is already taken by another user' });

    db.run(
      'UPDATE users SET name = ?, email = ?, about = ?, user_code = ? WHERE id = ?',
      [name, email, about, user_code, userId],
      function (updateErr) {
        if (updateErr) return res.status(500).json({ error: updateErr.message });
        res.json({ success: true, message: 'User updated successfully' });
      }
    );
  });
});

app.get('/admin/users/:id/chats', adminAuth, (req, res) => {
  const userId = req.params.id;
  db.all(`
    SELECT m.*, 
           u_sender.name as sender_name, u_sender.user_code as sender_code,
           u_receiver.name as receiver_name, u_receiver.user_code as receiver_code
    FROM messages m
    LEFT JOIN users u_sender ON m.sender_id = u_sender.id
    LEFT JOIN users u_receiver ON m.receiver_id = u_receiver.id
    WHERE m.sender_id = ? OR m.receiver_id = ?
    ORDER BY m.created_at DESC
  `, [userId, userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.delete('/admin/users/:id', adminAuth, (req, res) => {
  const userId = req.params.id;
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    db.serialize(() => {
      db.run('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', [userId, userId]);
      db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        const socketId = userSockets.get(parseInt(userId));
        if (socketId) {
          io.to(socketId).emit('force_logout', { reason: 'Account deleted by admin' });
          userSockets.delete(parseInt(userId));
        }
        res.json({ success: true, deleted_user: user.name });
      });
    });
  });
});

// ─── Users API ─────────────────────────────────────────────────

app.get('/admin/recordings', adminAuth, (req, res) => {
  db.all(`
    SELECT cr.*,
      u_caller.name AS caller_name, u_caller.user_code AS caller_code,
      u_receiver.name AS receiver_name, u_receiver.user_code AS receiver_code
    FROM call_recordings cr
    LEFT JOIN users u_caller ON cr.caller_id = u_caller.id
    LEFT JOIN users u_receiver ON cr.receiver_id = u_receiver.id
    ORDER BY cr.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

const ADMIN_EMAIL = 'theijazlegacy@gmail.com';

app.get('/api/users', requireAuth, (req, res) => {
  // Admin sees all users
  if (req.user.email === ADMIN_EMAIL) {
    db.all(
      'SELECT id, name, email, avatar, about, user_code FROM users WHERE id != ?',
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
      }
    );
    return;
  }

  // Regular users: only see people they've already had a conversation with, excluding fully deleted ones
  db.all(`
    SELECT DISTINCT u.id, u.name, u.email, u.avatar, u.about, u.user_code,
      (
        SELECT m.deleted_by FROM messages m 
        WHERE (m.sender_id = u.id AND m.receiver_id = ?) 
           OR (m.receiver_id = u.id AND m.sender_id = ?)
        ORDER BY m.created_at DESC LIMIT 1
      ) as last_deleted_by_json
    FROM users u
    INNER JOIN messages m
      ON (m.sender_id = u.id AND m.receiver_id = ?)
      OR (m.receiver_id = u.id AND m.sender_id = ?)
    WHERE u.id != ?
  `, [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Filter out rows where all messages are soft-deleted by the current user
    const filtered = rows.filter(r => {
      try {
        const deletedBy = JSON.parse(r.last_deleted_by_json || '[]');
        return !deletedBy.includes(req.user.id);
      } catch (e) {
        return true;
      }
    });

    res.json(filtered);
  });
});

// Search a user by their exact 4-digit unique code
app.get('/api/users/find', requireAuth, (req, res) => {
  const { code } = req.query;
  if (!code || !/^\d{4}$/.test(code)) {
    return res.status(400).json({ error: 'Please enter a valid 4-digit user ID' });
  }
  db.get(
    'SELECT id, name, email, avatar, about, user_code FROM users WHERE user_code = ? AND id != ?',
    [code, req.user.id],
    (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(404).json({ error: 'No user found with that ID' });
      res.json(user);
    }
  );
});

app.put('/api/users/profile', requireAuth, upload.single('avatar'), (req, res) => {
  const { name, about } = req.body;
  const userId = req.user.id;

  const saveProfile = (avatarUrl) => {
    db.run('UPDATE users SET name = ?, about = ?, avatar = ? WHERE id = ?', [name, about, avatarUrl, userId], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, name, about, avatar: avatarUrl });
    });
  };

  if (req.file) {
    if (USE_CLOUDINARY) {
      const uploadStream = cloudinary.uploader.upload_stream(
        { resource_type: 'image', folder: 'messenger_avatars' },
        (error, result) => {
          if (error) return res.status(500).json({ error: error.message });
          saveProfile(result.secure_url);
        }
      );
      streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
    } else {
      const uploadPath = path.join(__dirname, 'uploads');
      if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath);
      const filename = `${Date.now()}${path.extname(req.file.originalname)}`;
      fs.writeFileSync(path.join(uploadPath, filename), req.file.buffer);
      saveProfile(`http://localhost:${process.env.PORT || 3002}/uploads/${filename}`);
    }
  } else {
    saveProfile(req.user.avatar);
  }
});

app.get('/api/messages/:userId', requireAuth, (req, res) => {
  const otherUserId = req.params.userId;
  const currentUserId = req.user.id;
  
  db.all(
    `SELECT * FROM messages
     WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
     ORDER BY created_at ASC`,
    [currentUserId, otherUserId, otherUserId, currentUserId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      // Filter out messages that current user has soft-deleted
      const filtered = rows.filter(r => {
        try {
          const deletedBy = JSON.parse(r.deleted_by || '[]');
          return !deletedBy.includes(currentUserId);
        } catch (e) {
          return true;
        }
      });
      res.json(filtered);
    }
  );
});

// Soft delete chat with a user (clear chat / remove contact)
app.delete('/api/messages/:userId', requireAuth, (req, res) => {
  const otherUserId = req.params.userId;
  const currentUserId = req.user.id;

  // Retrieve all messages between users
  db.all(
    `SELECT id, deleted_by FROM messages 
     WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)`,
    [currentUserId, otherUserId, otherUserId, currentUserId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      
      const promises = rows.map(r => {
        return new Promise((resolve) => {
          let deletedBy = [];
          try {
            deletedBy = JSON.parse(r.deleted_by || '[]');
          } catch(e) {}
          if (!deletedBy.includes(currentUserId)) {
            deletedBy.push(currentUserId);
          }
          db.run(
            'UPDATE messages SET deleted_by = ? WHERE id = ?',
            [JSON.stringify(deletedBy), r.id],
            () => resolve()
          );
        });
      });

      Promise.all(promises).then(() => {
        res.json({ success: true, message: 'Chat deleted/removed successfully' });
      });
    }
  );
});

app.post('/api/messages/upload', requireAuth, upload.single('media'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  if (USE_CLOUDINARY) {
    // Stream buffer directly to Cloudinary
    const isImage = req.file.mimetype.startsWith('image/');
    const isVideo = req.file.mimetype.startsWith('video/');
    const resourceType = isVideo ? 'video' : isImage ? 'image' : 'raw';

    const uploadStream = cloudinary.uploader.upload_stream(
      { resource_type: resourceType, folder: 'messenger_uploads' },
      (error, result) => {
        if (error) return res.status(500).json({ error: error.message });
        res.json({ success: true, url: result.secure_url, type: req.file.mimetype });
      }
    );
    streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
  } else {
    // Local dev: save to disk
    const uploadPath = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadPath)) fs.mkdirSync(uploadPath);
    const filename = `${Date.now()}${path.extname(req.file.originalname)}`;
    const filepath = path.join(uploadPath, filename);
    fs.writeFileSync(filepath, req.file.buffer);
    const mediaUrl = `http://localhost:${process.env.PORT || 3002}/uploads/${filename}`;
    res.json({ success: true, url: mediaUrl, type: req.file.mimetype });
  }
});

// ─── Socket.IO ────────────────────────────────────────────────
const userSockets = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('register', (rawUserId) => {
    const userId = parseInt(rawUserId, 10);
    userSockets.set(userId, socket.id);
    socket.emit('online_users_list', Array.from(userSockets.keys()));
    socket.broadcast.emit('user_online', userId);
  });

  socket.on('get_online_users', () => {
    socket.emit('online_users_list', Array.from(userSockets.keys()));
  });

  socket.on('send_message', (data) => {
    const { sender_id, receiver_id, text, attachment_url, attachment_type } = data;
    db.run(
      'INSERT INTO messages (sender_id, receiver_id, text, attachment_url, attachment_type) VALUES (?, ?, ?, ?, ?)',
      [sender_id, receiver_id, text, attachment_url, attachment_type],
      function (err) {
        if (err) return console.error(err);
        const message = {
          id: this.lastID,
          sender_id, receiver_id, text, attachment_url, attachment_type,
          status: 'sent',
          created_at: new Date().toISOString()
        };
        socket.emit('receive_message', message);
        const receiverSocketId = userSockets.get(receiver_id);
        if (receiverSocketId) io.to(receiverSocketId).emit('receive_message', message);
      }
    );
  });

  socket.on('edit_message', (data) => {
    const { message_id, new_text } = data;
    db.get('SELECT * FROM messages WHERE id = ?', [message_id], (err, msg) => {
      if (err || !msg) return;
      if (Date.now() - new Date(msg.created_at).getTime() > 5 * 60 * 1000) return;
      db.run('UPDATE messages SET text = ?, is_edited = 1 WHERE id = ?', [new_text, message_id], function (err) {
        if (!err) {
          const updateData = { id: message_id, text: new_text, is_edited: 1 };
          const rSock = userSockets.get(msg.receiver_id);
          const sSock = userSockets.get(msg.sender_id);
          if (rSock) io.to(rSock).emit('message_updated', updateData);
          if (sSock) io.to(sSock).emit('message_updated', updateData);
        }
      });
    });
  });

  socket.on('delete_message', (data) => {
    const { message_id } = data;
    db.get('SELECT * FROM messages WHERE id = ?', [message_id], (err, msg) => {
      if (err || !msg) return;
      db.run('UPDATE messages SET is_deleted = 1, text = "This message was deleted" WHERE id = ?', [message_id], function (err) {
        if (!err) {
          const updateData = { id: message_id, is_deleted: 1, text: 'This message was deleted' };
          const rSock = userSockets.get(msg.receiver_id);
          const sSock = userSockets.get(msg.sender_id);
          if (rSock) io.to(rSock).emit('message_updated', updateData);
          if (sSock) io.to(sSock).emit('message_updated', updateData);
        }
      });
    });
  });

  socket.on('mark_seen', (data) => {
    const { sender_id, receiver_id } = data;
    db.run(
      'UPDATE messages SET status = "seen" WHERE sender_id = ? AND receiver_id = ? AND status != "seen"',
      [sender_id, receiver_id],
      function (err) {
        if (!err && this.changes > 0) {
          const sSock = userSockets.get(sender_id);
          if (sSock) {
            io.to(sSock).emit('messages_seen', { by_user_id: receiver_id });
          }
        }
      }
    );
  });
  // ─── WebRTC Signaling ───
  socket.on('call_user', (data) => {
    const receiverSocket = userSockets.get(data.userToCall);
    if (receiverSocket) {
      io.to(receiverSocket).emit('call_incoming', {
        signal: data.signalData,
        from: data.from,
        name: data.name,
        type: data.type
      });
    }
  });

  socket.on('answer_call', (data) => {
    const callerSocket = userSockets.get(data.to);
    if (callerSocket) {
      io.to(callerSocket).emit('call_accepted', data.signal);
    }
  });

  socket.on('ice_candidate', (data) => {
    const receiverSocket = userSockets.get(data.to);
    if (receiverSocket) {
      io.to(receiverSocket).emit('ice_candidate', data.candidate);
    }
  });

  socket.on('end_call', (data) => {
    const receiverSocket = userSockets.get(data.to);
    if (receiverSocket) {
      io.to(receiverSocket).emit('call_ended');
    }
  });

  socket.on('save_recording', (data) => {
    const { caller_id, receiver_id, call_type, recording_url, duration_seconds } = data;
    db.run(
      'INSERT INTO call_recordings (caller_id, receiver_id, call_type, recording_url, duration_seconds) VALUES (?, ?, ?, ?, ?)',
      [caller_id, receiver_id, call_type, recording_url, duration_seconds || 0],
      (err) => {
        if (err) console.error('[Recording] Failed to save:', err.message);
        else console.log('[Recording] Saved to DB:', recording_url);
      }
    );
  });

  socket.on('disconnect', () => {
    for (let [userId, socketId] of userSockets.entries()) {
      if (socketId === socket.id) {
        userSockets.delete(userId);
        socket.broadcast.emit('user_offline', userId);
        console.log(`User ${userId} went offline`);
        break;
      }
    }
  });
});

// ─── Start Server ──────────────────────────────────────────────
const PORT = process.env.PORT || 3002;
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use.`);
    process.exit(1);
  } else {
    console.error(err);
    process.exit(1);
  }
});

server.listen(PORT, () => {
  console.log(`\n✅ Messenger backend running on http://localhost:${PORT}`);
  console.log(`   Google Client ID: ${GOOGLE_CLIENT_ID.substring(0, 30)}...`);
});
