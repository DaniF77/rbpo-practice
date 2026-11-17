const express = require('express');
const app = express();
const sqlite3 = require('sqlite3');

app.use(express.urlencoded({ extended: true }));

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)');
  db.run("INSERT INTO users (username, password) VALUES ('admin', 'secret123'), ('sarah', 'sarah1995')");
});

// УЯЗВИМОСТЬ #1: SQL Injection (CWE-89)
app.get('/user', (req, res) => {
  const username = req.query.username;
  db.get(`SELECT * FROM users WHERE username = '${username}'`, (err, row) => { // ❌ конкатенация в SQL (CWE-89)
    res.json(row || { error: String(err) });
  });
});

// УЯЗВИМОСТЬ #2: XSS (CWE-79)
app.get('/hello', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Hello, ${name}!</h1>`); // ❌ Прямой вывод (CWE-79)
});

// УЯЗВИМОСТЬ #3: Command Injection (CWE-78)
app.get('/ping', (req, res) => {
  const host = req.query.host;
  const { exec } = require('child_process');
  exec(`ping -c 1 ${host}`, (error, stdout) => { // ❌ exec с пользовательским вводом (CWE-78)
    res.send(stdout);
  });
});

app.listen(3000, '127.0.0.1');
