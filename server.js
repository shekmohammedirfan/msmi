require('dotenv').config();
const express = require('express'), { Pool } = require('pg'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), cookieParser = require('cookie-parser'), path = require('path');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3 });
const q = (t, p) => pool.query(t, p);
if (process.env.VERCEL && !process.env.JWT_SECRET) throw new Error('Set JWT_SECRET in Vercel environment variables');
const SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
// Create tables once per server start (needed on Vercel, where functions start on demand)
let ready;
const boot = () => ready || (ready = init().catch(e => { ready = null; throw e; }));
app.use('/api', (req, res, next) => boot().then(() => next()).catch(e => { console.error(e); bad(res, 'Database connection failed. Check DATABASE_URL.', 500); }));
app.use(express.static(path.join(__dirname, 'public')));

const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const validUser = u => /^[A-Za-z0-9_.-]{3,30}$/.test(u || '');          // no "@" => no email usernames
const validPass = p => typeof p === 'string' && p.length >= 6 && p.length <= 100;
const PF = ['full_name', 'phone', 'dob', 'gender', 'occupation', 'organization', 'address', 'city', 'country', 'website', 'bio'];
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); bad(res, 'Server error. Please try again.', 500); });

// ---------- Database tables (created automatically) ----------
async function init() {
  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', created_at TIMESTAMPTZ DEFAULT now(),
    last_login TIMESTAMPTZ, last_seen TIMESTAMPTZ)`);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS users_name_uq ON users(lower(username))`);
  await q(`CREATE TABLE IF NOT EXISTS profiles(
    user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ${PF.map(k => k + " TEXT DEFAULT ''").join(',')}, avatar TEXT DEFAULT '', updated_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS messages(
    id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL, is_read BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT now())`);
  await q(`CREATE TABLE IF NOT EXISTS reset_requests(
    id SERIAL PRIMARY KEY, username TEXT NOT NULL, note TEXT DEFAULT '',
    status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT now())`);
  const a = await q(`SELECT 1 FROM users WHERE role='admin'`);
  if (!a.rows.length) {   // first start only: create the administrator
    await q(`INSERT INTO users(username,password_hash,role) VALUES($1,$2,'admin')`,
      ['ADMINMSMI', await bcrypt.hash('MSMI2008@SHEK', 10)]);
    console.log('Administrator account created.');
  }
}

// ---------- Login check ----------
const auth = role => async (req, res, next) => {
  try {
    const d = jwt.verify(req.cookies.t, SECRET);
    const r = await q('SELECT id,username,role FROM users WHERE id=$1', [d.id]);
    if (!r.rows[0]) throw new Error('gone');
    if (role && r.rows[0].role !== role) return bad(res, 'Not allowed', 403);
    req.user = r.rows[0]; next();
  } catch { bad(res, 'Please log in', 401); }
};

// ---------- Public routes ----------
app.post('/api/login', wrap(async (req, res) => {
  const { username, password, admin } = req.body;
  const u = (await q('SELECT * FROM users WHERE lower(username)=lower($1)', [String(username || '')])).rows[0];
  if (!u || !(await bcrypt.compare(String(password || ''), u.password_hash))) return bad(res, 'Wrong username or password', 401);
  if (!!admin !== (u.role === 'admin')) return bad(res, admin ? 'This is not an administrator account' : 'Administrators must use the Admin Login tab', 403);
  await q('UPDATE users SET last_login=now(), last_seen=now() WHERE id=$1', [u.id]);
  res.cookie('t', jwt.sign({ id: u.id }, SECRET, { expiresIn: '8h' }), { httpOnly: true, sameSite: 'strict', secure: !!process.env.VERCEL, maxAge: 8 * 3600 * 1000 });
  res.json({ role: u.role });
}));

app.post('/api/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: true }); });

// Reset option 1: change by entering the old password
app.post('/api/reset/change', wrap(async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  if (!validPass(newPassword)) return bad(res, 'New password must be at least 6 characters');
  const u = (await q(`SELECT * FROM users WHERE lower(username)=lower($1) AND role='user'`, [String(username || '')])).rows[0];
  if (!u || !(await bcrypt.compare(String(oldPassword || ''), u.password_hash))) return bad(res, 'Username or old password is wrong', 401);
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(newPassword, 10), u.id]);
  res.json({ ok: true });
}));

// Reset option 2: ask the administrator to change it
app.post('/api/reset/request', wrap(async (req, res) => {
  const name = String(req.body.username || '').trim(), note = String(req.body.note || '').slice(0, 300);
  const u = (await q(`SELECT username FROM users WHERE lower(username)=lower($1) AND role='user'`, [name])).rows[0];
  if (u) {
    const dup = await q(`SELECT 1 FROM reset_requests WHERE username=$1 AND status='pending'`, [u.username]);
    if (!dup.rows.length) await q('INSERT INTO reset_requests(username,note) VALUES($1,$2)', [u.username, note]);
  }
  res.json({ ok: true }); // same answer either way, so nobody can test which usernames exist
}));

// ---------- Logged-in user routes ----------
app.get('/api/me', auth(), wrap(async (req, res) => {
  await q('UPDATE users SET last_seen=now() WHERE id=$1', [req.user.id]);
  res.json({ username: req.user.username, role: req.user.role });
}));

app.get('/api/profile', auth('user'), wrap(async (req, res) => {
  const r = await q(`SELECT u.username,u.created_at,u.last_login,p.* FROM users u
    LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=$1`, [req.user.id]);
  res.json(r.rows[0]);
}));

app.put('/api/profile', auth('user'), wrap(async (req, res) => {
  const vals = PF.map(k => String(req.body[k] ?? '').slice(0, k === 'bio' ? 500 : 150));
  let av = null;
  if (typeof req.body.avatar === 'string' && (req.body.avatar === '' || (req.body.avatar.startsWith('data:image/') && req.body.avatar.length < 300000))) av = req.body.avatar;
  await q(`INSERT INTO profiles(user_id,${PF.join(',')},avatar) VALUES($1,${PF.map((_, i) => '$' + (i + 2)).join(',')},$${PF.length + 2})
    ON CONFLICT(user_id) DO UPDATE SET ${PF.map(k => k + '=EXCLUDED.' + k).join(',')},
    avatar=COALESCE(EXCLUDED.avatar,profiles.avatar), updated_at=now()`, [req.user.id, ...vals, av]);
  res.json({ ok: true });
}));

app.get('/api/messages', auth('user'), wrap(async (req, res) => {
  res.json((await q('SELECT id,body,is_read,created_at FROM messages WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id])).rows);
}));
app.post('/api/messages/read', auth('user'), wrap(async (req, res) => {
  await q('UPDATE messages SET is_read=true WHERE user_id=$1', [req.user.id]); res.json({ ok: true });
}));

app.post('/api/change-password', auth(), wrap(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!validPass(newPassword)) return bad(res, 'New password must be at least 6 characters');
  const u = (await q('SELECT password_hash FROM users WHERE id=$1', [req.user.id])).rows[0];
  if (!(await bcrypt.compare(String(oldPassword || ''), u.password_hash))) return bad(res, 'Current password is wrong', 401);
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(newPassword, 10), req.user.id]);
  res.json({ ok: true });
}));

// ---------- Administrator routes ----------
const admin = auth('admin');

app.get('/api/admin/users', admin, wrap(async (req, res) => {
  res.json((await q(`SELECT u.id,u.username,u.created_at,u.last_login,(u.last_seen > now() - interval '2 minutes') AS online,
    p.full_name,p.city,(SELECT count(*) FROM messages m WHERE m.user_id=u.id AND NOT m.is_read)::int AS unread
    FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.role='user' ORDER BY lower(u.username)`)).rows);
}));

app.get('/api/admin/users/:id', admin, wrap(async (req, res) => {
  const r = await q(`SELECT u.id,u.username,u.created_at,u.last_login,u.last_seen,p.* FROM users u
    LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=$1 AND u.role='user'`, [req.params.id]);
  if (!r.rows[0]) return bad(res, 'User not found', 404);
  const m = await q('SELECT body,is_read,created_at FROM messages WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [req.params.id]);
  res.json({ ...r.rows[0], messages: m.rows });
}));

app.post('/api/admin/users', admin, wrap(async (req, res) => {
  const { username, password } = req.body;
  if (!validUser(username)) return bad(res, 'Username: 3-30 letters, numbers, dot, dash or underscore (no email)');
  if (!validPass(password)) return bad(res, 'Password must be at least 6 characters');
  try {
    const r = await q(`INSERT INTO users(username,password_hash) VALUES($1,$2) RETURNING id`, [username, await bcrypt.hash(password, 10)]);
    await q('INSERT INTO profiles(user_id) VALUES($1)', [r.rows[0].id]);
    res.json({ ok: true });
  } catch (e) { if (e.code === '23505') return bad(res, 'That username already exists'); throw e; }
}));

app.delete('/api/admin/users/:id', admin, wrap(async (req, res) => {
  await q(`DELETE FROM users WHERE id=$1 AND role='user'`, [req.params.id]); res.json({ ok: true });
}));

app.put('/api/admin/users/:id/password', admin, wrap(async (req, res) => {
  if (!validPass(req.body.password)) return bad(res, 'Password must be at least 6 characters');
  const r = await q(`UPDATE users SET password_hash=$1 WHERE id=$2 AND role='user' RETURNING username`, [await bcrypt.hash(req.body.password, 10), req.params.id]);
  if (!r.rows[0]) return bad(res, 'User not found', 404);
  await q(`UPDATE reset_requests SET status='done' WHERE username=$1 AND status='pending'`, [r.rows[0].username]);
  res.json({ ok: true });
}));

app.post('/api/admin/messages', admin, wrap(async (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 1000), to = req.body.userId;
  if (!body) return bad(res, 'Write a message first');
  if (to === 'all') await q(`INSERT INTO messages(user_id,body) SELECT id,$1 FROM users WHERE role='user'`, [body]);
  else await q(`INSERT INTO messages(user_id,body) SELECT id,$1 FROM users WHERE id=$2 AND role='user'`, [body, to]);
  res.json({ ok: true });
}));

app.get('/api/admin/requests', admin, wrap(async (req, res) => {
  res.json((await q(`SELECT * FROM reset_requests WHERE status='pending' ORDER BY created_at`)).rows);
}));
app.post('/api/admin/requests/:id/resolve', admin, wrap(async (req, res) => {
  if (!validPass(req.body.password)) return bad(res, 'Password must be at least 6 characters');
  const rq = (await q('SELECT username FROM reset_requests WHERE id=$1', [req.params.id])).rows[0];
  if (!rq) return bad(res, 'Request not found', 404);
  await q(`UPDATE users SET password_hash=$1 WHERE lower(username)=lower($2) AND role='user'`, [await bcrypt.hash(req.body.password, 10), rq.username]);
  await q(`UPDATE reset_requests SET status='done' WHERE id=$1`, [req.params.id]);
  res.json({ ok: true });
}));
app.delete('/api/admin/requests/:id', admin, wrap(async (req, res) => {
  await q(`UPDATE reset_requests SET status='dismissed' WHERE id=$1`, [req.params.id]); res.json({ ok: true });
}));

// Change the administrator's own password
app.put('/api/admin/password', admin, wrap(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!validPass(newPassword)) return bad(res, 'New password must be at least 6 characters');
  const u = (await q('SELECT password_hash FROM users WHERE id=$1', [req.user.id])).rows[0];
  if (!(await bcrypt.compare(String(oldPassword || ''), u.password_hash))) return bad(res, 'Current password is wrong', 401);
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(newPassword, 10), req.user.id]);
  res.json({ ok: true });
}));

module.exports = app;   // Vercel uses this

if (require.main === module) {   // "npm start" on your own computer
  const port = process.env.PORT || 3000;
  boot().then(() => app.listen(port, () => console.log('MSMI running: http://localhost:' + port)))
    .catch(e => { console.error('Database connection failed. Check DATABASE_URL in .env\n', e.message); process.exit(1); });
}
