const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'asznee-secret-key-change-in-production';

// File size limit: 1GB
const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB in bytes

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database setup
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'asznee.db');
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT,
    content TEXT,
    color TEXT DEFAULT '0',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    date TEXT NOT NULL,
    time TEXT,
    type TEXT DEFAULT 'schedule',
    priority TEXT DEFAULT 'medium',
    completed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    type TEXT,
    size INTEGER,
    category TEXT DEFAULT 'other',
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: MAX_FILE_SIZE // 1GB limit
  }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
};

// Get file category based on mimetype
function getFileCategory(mimetype) {
  if (mimetype.startsWith('image/')) return 'image';
  if (mimetype.startsWith('video/')) return 'video';
  if (mimetype.startsWith('audio/')) return 'audio';
  if (mimetype === 'application/pdf' || 
      mimetype.includes('document') || 
      mimetype.includes('text/')) return 'document';
  if (mimetype.includes('zip') || 
      mimetype.includes('compressed') ||
      mimetype.includes('archive')) return 'archive';
  return 'other';
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'ASZNEE API is running', maxFileSize: '1GB' });
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: 'Failed to create user' });
        }

        const token = jwt.sign(
          { userId: this.lastID, username, email },
          JWT_SECRET,
          { expiresIn: '30d' }
        );

        res.status(201).json({
          message: 'User created successfully',
          token,
          user: { id: this.lastID, username, email }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    db.get(
      'SELECT * FROM users WHERE email = ?',
      [email],
      async (err, user) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { userId: user.id, username: user.username, email: user.email },
          JWT_SECRET,
          { expiresIn: '30d' }
        );

        res.json({
          message: 'Login successful',
          token,
          user: { id: user.id, username: user.username, email: user.email }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(
    'SELECT id, username, email, created_at FROM users WHERE id = ?',
    [req.user.userId],
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json({ user });
    }
  );
});

// Dashboard
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  
  db.get('SELECT COUNT(*) as count FROM notes WHERE user_id = ?', [userId], (err, notesCount) => {
    db.get('SELECT COUNT(*) as count FROM events WHERE user_id = ?', [userId], (err, eventsCount) => {
      db.get('SELECT COUNT(*) as count FROM files WHERE user_id = ?', [userId], (err, filesCount) => {
        db.get('SELECT COUNT(*) as count FROM files WHERE user_id = ? AND category = ?', [userId, 'image'], (err, imageCount) => {
          db.get('SELECT COUNT(*) as count FROM files WHERE user_id = ? AND category = ?', [userId, 'video'], (err, videoCount) => {
            db.all('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC LIMIT 5', [userId], (err, recentNotes) => {
              db.all('SELECT * FROM events WHERE user_id = ? AND date >= date("now") ORDER BY date ASC LIMIT 5', [userId], (err, upcomingEvents) => {
                db.all('SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC LIMIT 5', [userId], (err, recentFiles) => {
                  res.json({
                    stats: {
                      totalNotes: notesCount?.count || 0,
                      totalEvents: eventsCount?.count || 0,
                      totalFiles: filesCount?.count || 0,
                      imageCount: imageCount?.count || 0,
                      videoCount: videoCount?.count || 0,
                      otherCount: (filesCount?.count || 0) - (imageCount?.count || 0) - (videoCount?.count || 0)
                    },
                    recentNotes: recentNotes || [],
                    upcomingEvents: upcomingEvents || [],
                    recentFiles: recentFiles || []
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

// Notes routes
app.get('/api/notes', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC',
    [req.user.userId],
    (err, notes) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch notes' });
      }
      res.json(notes);
    }
  );
});

app.post('/api/notes', authenticateToken, (req, res) => {
  const { title, content, color } = req.body;
  db.run(
    'INSERT INTO notes (user_id, title, content, color) VALUES (?, ?, ?, ?)',
    [req.user.userId, title || '', content || '', color || '0'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create note' });
      }
      db.get('SELECT * FROM notes WHERE id = ?', [this.lastID], (err, note) => {
        res.status(201).json(note);
      });
    }
  );
});

app.put('/api/notes/:id', authenticateToken, (req, res) => {
  const { title, content, color } = req.body;
  db.run(
    'UPDATE notes SET title = ?, content = ?, color = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
    [title, content, color, req.params.id, req.user.userId],
    function(err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'Note not found' });
      }
      db.get('SELECT * FROM notes WHERE id = ?', [req.params.id], (err, note) => {
        res.json(note);
      });
    }
  );
});

app.delete('/api/notes/:id', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM notes WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.userId],
    function(err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'Note not found' });
      }
      res.json({ message: 'Note deleted' });
    }
  );
});

// Events routes
app.get('/api/events', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM events WHERE user_id = ? ORDER BY date ASC',
    [req.user.userId],
    (err, events) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch events' });
      }
      res.json(events);
    }
  );
});

app.post('/api/events', authenticateToken, (req, res) => {
  const { title, description, date, time, type, priority } = req.body;
  db.run(
    'INSERT INTO events (user_id, title, description, date, time, type, priority) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [req.user.userId, title, description || '', date, time || '', type || 'schedule', priority || 'medium'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create event' });
      }
      db.get('SELECT * FROM events WHERE id = ?', [this.lastID], (err, event) => {
        res.status(201).json(event);
      });
    }
  );
});

app.put('/api/events/:id', authenticateToken, (req, res) => {
  const { title, description, date, time, type, priority, completed } = req.body;
  const updates = [];
  const values = [];

  if (title !== undefined) { updates.push('title = ?'); values.push(title); }
  if (description !== undefined) { updates.push('description = ?'); values.push(description); }
  if (date !== undefined) { updates.push('date = ?'); values.push(date); }
  if (time !== undefined) { updates.push('time = ?'); values.push(time); }
  if (type !== undefined) { updates.push('type = ?'); values.push(type); }
  if (priority !== undefined) { updates.push('priority = ?'); values.push(priority); }
  if (completed !== undefined) { updates.push('completed = ?'); values.push(completed ? 1 : 0); }

  values.push(req.params.id, req.user.userId);

  db.run(
    `UPDATE events SET ${updates.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?`,
    values,
    function(err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'Event not found' });
      }
      db.get('SELECT * FROM events WHERE id = ?', [req.params.id], (err, event) => {
        res.json(event);
      });
    }
  );
});

app.delete('/api/events/:id', authenticateToken, (req, res) => {
  db.run(
    'DELETE FROM events WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.userId],
    function(err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'Event not found' });
      }
      res.json({ message: 'Event deleted' });
    }
  );
});

// Files routes
app.get('/api/files', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC',
    [req.user.userId],
    (err, files) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch files' });
      }
      res.json(files);
    }
  );
});

app.post('/api/files', authenticateToken, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const category = getFileCategory(req.file.mimetype);

    db.run(
      'INSERT INTO files (user_id, name, filename, type, size, category) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.userId, req.file.originalname, req.file.filename, req.file.mimetype, req.file.size, category],
      function(err) {
        if (err) {
          // Delete the uploaded file if DB insert fails
          fs.unlinkSync(req.file.path);
          return res.status(500).json({ error: 'Failed to save file info' });
        }
        db.get('SELECT * FROM files WHERE id = ?', [this.lastID], (err, file) => {
          res.status(201).json(file);
        });
      }
    );
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

app.delete('/api/files/:id', authenticateToken, (req, res) => {
  db.get(
    'SELECT * FROM files WHERE id = ? AND user_id = ?',
    [req.params.id, req.user.userId],
    (err, file) => {
      if (err || !file) {
        return res.status(404).json({ error: 'File not found' });
      }

      // Delete from filesystem
      const filePath = path.join(uploadsDir, file.filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      // Delete from database
      db.run(
        'DELETE FROM files WHERE id = ? AND user_id = ?',
        [req.params.id, req.user.userId],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to delete file' });
          }
          res.json({ message: 'File deleted' });
        }
      );
    }
  );
});

// Error handling for multer (file too large)
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ 
        error: 'File too large. Maximum file size is 1GB.',
        maxSize: '1GB'
      });
    }
    return res.status(400).json({ error: error.message });
  }
  next(error);
});

// Start server
app.listen(PORT, () => {
  console.log(`ASZNEE API Server running on port ${PORT}`);
  console.log(`Max file upload size: 1GB`);
  console.log(`Database: ${dbPath}`);
});
