const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Kunci rahasia untuk JWT (Sebaiknya gunakan Environment Variable di Vercel nanti)
const JWT_SECRET = 'rahasia_tugas_guwe_123';

// Gunakan createPool agar koneksi tidak mudah terputus di lingkungan serverless Vercel
const db = mysql.createPool({
  host: 'mysql-347138f2-vankhadafi-cc19.l.aivencloud.com', 
  port: 14404,
  user: 'avnadmin',
  password: 'AVNS_Yh8GC7kbZ9beoKYAFa3',
  database: 'defaultdb',
  ssl: { rejectUnauthorized: false }
});

// ==========================================
// MIDDLEWARE: Cek Token
// ==========================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

  if (!token) return res.status(401).json({ error: 'Akses ditolak. Token tidak ada.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token tidak valid atau kedaluwarsa.' });
    req.user = user; // Simpan data user ke request
    next();
  });
};

// ==========================================
// SETUP DATABASE (RESET TABEL)
// ==========================================
app.get('/api/setup', (req, res) => {
  // PERHATIAN: Menghapus tabel tasks lama agar struktur baru (dengan userId) bisa dibuat tanpa bentrok
  db.query('DROP TABLE IF EXISTS tasks', (errDrop) => {
    if (errDrop) return res.status(500).json({ error: 'Gagal mereset tabel tasks: ' + errDrop.message });

    const queryCreateUsers = `
      CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(50) PRIMARY KEY,
          username VARCHAR(100) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL
      )
    `;
    
    const queryCreateTasks = `
      CREATE TABLE IF NOT EXISTS tasks (
          id VARCHAR(50) PRIMARY KEY,
          userId VARCHAR(50) NOT NULL,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          status VARCHAR(50) DEFAULT 'todo',
          priority VARCHAR(50) DEFAULT 'medium',
          deadline DATE NULL,
          category VARCHAR(100),
          createdAt VARCHAR(50),
          updatedAt VARCHAR(50),
          FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      )
    `;
    
    db.query(queryCreateUsers, (err1) => {
      if (err1) return res.status(500).json({ error: 'Gagal buat tabel users: ' + err1.message });
      
      db.query(queryCreateTasks, (err2) => {
        if (err2) return res.status(500).json({ error: 'Gagal buat tabel tasks: ' + err2.message });
        res.json({ message: 'Tabel database berhasil di-reset dan siap digunakan!' });
      });
    });
  });
});

// ==========================================
// AUTENTIKASI (REGISTER & LOGIN)
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username dan password wajib diisi!' });

  try {
    // Hash password agar aman
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = Date.now().toString(36); // Generate ID sederhana
    
    db.query('INSERT INTO users (id, username, password) VALUES (?, ?, ?)', [id, username, hashedPassword], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Username sudah terpakai!' });
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Registrasi berhasil! Silakan login.' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Terjadi kesalahan pada server' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(400).json({ error: 'Username tidak ditemukan!' });

    const user = results[0];
    
    // Cek kecocokan password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Password salah!' });

    // Buat Token
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ message: 'Login berhasil!', token });
  });
});

// ==========================================
// CRUD TUGAS (DIAMANKAN DENGAN TOKEN)
// ==========================================

// 1. Mengambil Tugas (Hanya milik user yang login)
app.get('/api/tasks', authenticateToken, (req, res) => {
  db.query('SELECT * FROM tasks WHERE userId = ?', [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// 2. Menyimpan Tugas Baru
app.post('/api/tasks', authenticateToken, (req, res) => {
  const { id, title, desc, status, priority, deadline, category, createdAt, updatedAt } = req.body;
  const userId = req.user.id; // Diambil dari token
  
  const query = 'INSERT INTO tasks (id, userId, title, description, status, priority, deadline, category, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
  
  db.query(query, [id, userId, title, desc, status, priority, deadline || null, category, createdAt, updatedAt], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Tugas berhasil disimpan!' });
  });
});

// 3. Memperbarui Tugas (Hanya jika tugas milik user tersebut)
app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const { title, desc, status, priority, deadline, category, updatedAt } = req.body;
  const query = 'UPDATE tasks SET title=?, description=?, status=?, priority=?, deadline=?, category=?, updatedAt=? WHERE id=? AND userId=?';
  
  db.query(query, [title, desc, status, priority, deadline || null, category, updatedAt, req.params.id, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Tugas berhasil diperbarui!' });
  });
});

// 4. Menghapus Tugas
app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
  db.query('DELETE FROM tasks WHERE id=? AND userId=?', [req.params.id, req.user.id], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Tugas berhasil dihapus!' });
  });
});

module.exports = app;
