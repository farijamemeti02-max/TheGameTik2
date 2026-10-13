'use strict';
require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const MAX_VIDEO_BYTES = 35 * 1000 * 1000;
const MAX_AVATAR_BYTES = 3 * 1024 * 1024;
const rateBuckets = new Map();
function rateLimit({ windowMs, max, message }) {
  return (req, res, next) => {
    const now = Date.now();
    const routeKey = req.route && req.route.path ? String(req.route.path) : req.path;
    const key = `${req.ip || req.socket.remoteAddress || 'unknown'}:${req.baseUrl}${routeKey}`;
    let bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) bucket = { count: 0, resetAt: now + windowMs };
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    if (rateBuckets.size > 10000) { for (const [k, v] of rateBuckets) if (v.resetAt <= now) rateBuckets.delete(k); }
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, max - bucket.count)));
    res.setHeader('RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));
    if (bucket.count > max) return res.status(429).json({ error: message });
    next();
  };
}
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const videoDir = path.join(uploadDir, 'videos');
const avatarDir = path.join(uploadDir, 'avatars');
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET muss gesetzt sein und mindestens 32 Zeichen haben.');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('FATAL: DATABASE_URL fehlt. Verbinde eine PostgreSQL-Datenbank in Render.');
  process.exit(1);
}
for (const dir of [videoDir, avatarDir]) fs.mkdirSync(dir, { recursive: true });
const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false } });
const io = new Server(server, {
  cors: { origin: true, credentials: true, methods: ['GET', 'POST'] },
  maxHttpBufferSize: 1e6
});
app.set('trust proxy', 1);
app.use(cors({ origin: true, credentials: true, methods: ['GET','POST','PATCH','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use('/uploads', express.static(uploadDir, { maxAge: '1h', immutable: true }));
app.get('/', (_req, res) => res.json({ name: 'GAMETIKA API', status: 'ok', maxVideoUploadMB: 35 }));
app.get('/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch (_e) { res.status(503).json({ ok: false, database: 'unavailable' }); }
});

const videoStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, videoDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${cryptoRandom()}${path.extname(file.originalname).toLowerCase()}`)
});
const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, avatarDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${cryptoRandom()}${path.extname(file.originalname).toLowerCase()}`)
});
function cryptoRandom() { return require('crypto').randomBytes(12).toString('hex'); }
async function hasExpectedSignature(filePath, kind, ext) {
  const handle = await fs.promises.open(filePath, 'r');
  try {
    const buffer = Buffer.alloc(16);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (kind === 'avatar') {
      if (['.jpg', '.jpeg'].includes(ext)) return bytesRead >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
      if (ext === '.png') return bytesRead >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
      if (ext === '.webp') return bytesRead >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP';
      return false;
    }
    if (ext === '.webm') return bytesRead >= 4 && buffer[0] === 0x1a && buffer[1] === 0x45 && buffer[2] === 0xdf && buffer[3] === 0xa3;
    if (['.mp4', '.mov'].includes(ext)) {
      if (bytesRead < 12 || buffer.toString('ascii', 4, 8) !== 'ftyp') return false;
      const brand = buffer.toString('ascii', 8, 12);
      return ext === '.mov' ? brand === 'qt  ' : brand !== 'qt  ';
    }
    return false;
  } finally { await handle.close(); }
}
const videoUpload = multer({ storage: videoStorage, limits: { fileSize: MAX_VIDEO_BYTES, files: 1, fields: 10 }, fileFilter: (_req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const allowed = ['.mp4','.webm','.mov'];
  if (!allowed.includes(ext) || !['video/mp4','video/webm','video/quicktime','application/octet-stream'].includes(file.mimetype)) return cb(new Error('Nur MP4, WebM oder MOV sind erlaubt.'));
  cb(null, true);
} });
const avatarUpload = multer({ storage: avatarStorage, limits: { fileSize: MAX_AVATAR_BYTES, files: 1 }, fileFilter: (_req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!['.jpg','.jpeg','.png','.webp'].includes(ext) || !['image/jpeg','image/png','image/webp'].includes(file.mimetype)) return cb(new Error('Profilbild muss JPG, PNG oder WebP sein.'));
  cb(null, true);
} });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, username VARCHAR(24) UNIQUE NOT NULL,
      display_name VARCHAR(40) NOT NULL, password_hash TEXT NOT NULL,
      bio VARCHAR(300) NOT NULL DEFAULT '', avatar TEXT, role VARCHAR(16) NOT NULL DEFAULT 'user',
      disabled BOOLEAN NOT NULL DEFAULT FALSE, token_version INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS videos (
      id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(100) NOT NULL, description VARCHAR(500) NOT NULL DEFAULT '', url TEXT NOT NULL,
      filename TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS likes (user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, video_id BIGINT REFERENCES videos(id) ON DELETE CASCADE, PRIMARY KEY(user_id,video_id));
    CREATE TABLE IF NOT EXISTS comments (id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, video_id BIGINT REFERENCES videos(id) ON DELETE CASCADE, text VARCHAR(500) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS follows (follower_id BIGINT REFERENCES users(id) ON DELETE CASCADE, followed_id BIGINT REFERENCES users(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(follower_id,followed_id), CHECK(follower_id <> followed_id));
    CREATE TABLE IF NOT EXISTS messages (id BIGSERIAL PRIMARY KEY, from_id BIGINT REFERENCES users(id) ON DELETE CASCADE, to_id BIGINT REFERENCES users(id) ON DELETE CASCADE, text VARCHAR(1000) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS public_messages (id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, text VARCHAR(1000) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
  `);
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    const username = process.env.ADMIN_USERNAME.toLowerCase().trim();
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query(`INSERT INTO users(username,display_name,password_hash,role) VALUES($1,$2,$3,'admin') ON CONFLICT(username) DO UPDATE SET role='admin', password_hash=EXCLUDED.password_hash, display_name=EXCLUDED.display_name, disabled=FALSE, token_version=users.token_version+1`, [username, process.env.ADMIN_DISPLAY_NAME || 'GAMETIKA Admin', hash]);
  }
}
const publicUser = u => ({ id: String(u.id), username: u.username, displayName: u.display_name, bio: u.bio || '', avatar: u.avatar || null, role: u.role });
function makeToken(u) { return jwt.sign({ id: String(u.id), tv: Number(u.token_version || 0) }, JWT_SECRET, { expiresIn: '7d', issuer: 'gametika' }); }
async function auth(req, res, next) {
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!raw) return res.status(401).json({ error: 'Bitte anmelden.' });
  try {
    const payload = jwt.verify(raw, JWT_SECRET, { issuer: 'gametika' });
    const result = await pool.query('SELECT * FROM users WHERE id=$1 AND disabled=FALSE', [payload.id]);
    if (!result.rowCount) return res.status(401).json({ error: 'Konto nicht gefunden oder gesperrt.' });
    if (Number(payload.tv || 0) !== Number(result.rows[0].token_version || 0)) return res.status(401).json({ error: 'Sitzung wurde beendet. Bitte erneut anmelden.' });
    req.user = result.rows[0]; next();
  } catch (_e) { return res.status(401).json({ error: 'Sitzung ungültig oder abgelaufen. Bitte erneut anmelden.' }); }
}
const admin = (req,res,next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Nur Administratoren dürfen diese Aktion ausführen.' });
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const validId = value => { const s=String(value ?? ''); if(!/^[1-9]\d{0,18}$/.test(s)) return false; try { return BigInt(s) <= 9223372036854775807n; } catch { return false; } };

app.post('/api/register', rateLimit({ windowMs: 60 * 60 * 1000, max: 8, message: 'Zu viele Registrierungsversuche. Bitte später erneut versuchen.' }), asyncRoute(async (req,res) => {
  let { username, displayName, password } = req.body || {};
  username = String(username || '').trim().toLowerCase(); displayName = String(displayName || '').trim(); password = String(password || '');
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: 'Benutzername: 3–24 Zeichen, nur Buchstaben, Zahlen und Unterstrich.' });
  if (displayName.length < 2 || displayName.length > 40) return res.status(400).json({ error: 'Anzeigename muss 2–40 Zeichen haben.' });
  if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen haben.' });
  const hash = await bcrypt.hash(password, 12);
  try { const r = await pool.query('INSERT INTO users(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING *',[username,displayName,hash]); const u=r.rows[0]; res.status(201).json({ token:makeToken(u), user:publicUser(u) }); }
  catch (e) { if(e.code==='23505') return res.status(409).json({ error:'Dieser Benutzername ist bereits vergeben.' }); throw e; }
}));
app.post('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Zu viele Anmeldeversuche. Bitte 15 Minuten warten.' }), asyncRoute(async (req,res) => {
  const username=String(req.body?.username||'').trim().toLowerCase(), password=String(req.body?.password||'');
  const r=await pool.query('SELECT * FROM users WHERE username=$1',[username]);
  if(!r.rowCount || r.rows[0].disabled || !(await bcrypt.compare(password,r.rows[0].password_hash))) return res.status(401).json({error:'Benutzername oder Passwort ist falsch.'});
  res.json({token:makeToken(r.rows[0]),user:publicUser(r.rows[0])});
}));
app.post('/api/logout', auth, asyncRoute(async (req,res) => { await pool.query('UPDATE users SET token_version=token_version+1 WHERE id=$1', [req.user.id]); io.in('user:'+String(req.user.id)).disconnectSockets(true); res.json({ok:true}); }));
app.get('/api/me', auth, (req,res) => res.json({user:publicUser(req.user)}));
app.patch('/api/profile', auth, asyncRoute(async (req,res) => {
  const displayName=String(req.body?.displayName||'').trim(), bio=String(req.body?.bio||'').trim();
  if(displayName.length<2||displayName.length>40) return res.status(400).json({error:'Anzeigename muss 2–40 Zeichen haben.'});
  if(bio.length>300) return res.status(400).json({error:'Über mich darf maximal 300 Zeichen haben.'});
  const r=await pool.query('UPDATE users SET display_name=$1,bio=$2 WHERE id=$3 RETURNING *',[displayName,bio,req.user.id]);res.json({user:publicUser(r.rows[0])});
}));
app.post('/api/profile/avatar', auth, rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: 'Zu viele Profilbild-Uploads. Bitte später erneut versuchen.' }), (req,res,next) => avatarUpload.single('avatar')(req,res,err=>{if(err)return next(err);next();}), asyncRoute(async (req,res) => {
  if(!req.file) return res.status(400).json({error:'Bitte ein Profilbild auswählen.'});
  if (!(await hasExpectedSignature(req.file.path, 'avatar', path.extname(req.file.originalname).toLowerCase()))) { await fs.promises.unlink(req.file.path).catch(()=>{}); return res.status(400).json({error:'Die Datei ist kein gültiges JPG-, PNG- oder WebP-Bild.'}); }
  const oldAvatar=req.user.avatar ? path.basename(req.user.avatar) : null;
  const url='/uploads/avatars/'+req.file.filename;
  try {
    const r=await pool.query('UPDATE users SET avatar=$1 WHERE id=$2 RETURNING *',[url,req.user.id]);
    if(oldAvatar){const oldPath=path.join(avatarDir,oldAvatar);if(fs.existsSync(oldPath))fs.unlink(oldPath,()=>{});}
    res.json({user:publicUser(r.rows[0])});
  } catch(e) { fs.unlink(req.file.path,()=>{}); throw e; }
}));
app.get('/api/videos', asyncRoute(async (_req,res) => {
  const r=await pool.query(`SELECT v.id,v.title,v.description,v.url,v.created_at,u.display_name AS owner_name,
    (SELECT COUNT(*)::int FROM likes l WHERE l.video_id=v.id) AS likes,
    (SELECT COUNT(*)::int FROM comments c WHERE c.video_id=v.id) AS comment_count
    FROM videos v JOIN users u ON u.id=v.user_id WHERE u.disabled=FALSE ORDER BY v.created_at DESC LIMIT 100`);
  res.json({videos:r.rows.map(v=>({id:String(v.id),title:v.title,description:v.description,url:v.url,ownerName:v.owner_name,likes:v.likes,commentCount:v.comment_count,createdAt:v.created_at}))});
}));
app.post('/api/videos', auth, rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: 'Zu viele Video-Uploads. Bitte später erneut versuchen.' }), (req,res,next) => videoUpload.single('file')(req,res,err=>{if(err)return next(err);next();}), asyncRoute(async (req,res) => {
  if(!req.file) return res.status(400).json({error:'Bitte ein Video auswählen.'});
  if (!(await hasExpectedSignature(req.file.path, 'video', path.extname(req.file.originalname).toLowerCase()))) { await fs.promises.unlink(req.file.path).catch(()=>{}); return res.status(400).json({error:'Die Datei hat keinen gültigen MP4-, WebM- oder MOV-Dateikopf.'}); }
  const title=String(req.body?.title||'').trim(), description=String(req.body?.description||'').trim();
  if(!title||title.length>100||description.length>500){fs.unlink(req.file.path,()=>{});return res.status(400).json({error:'Titel ist erforderlich (max. 100 Zeichen), Beschreibung maximal 500 Zeichen.'});}
  const url='/uploads/videos/'+req.file.filename;
  try {
    const r=await pool.query('INSERT INTO videos(user_id,title,description,url,filename) VALUES($1,$2,$3,$4,$5) RETURNING id,title,description,url,created_at',[req.user.id,title,description,url,req.file.filename]);
    res.status(201).json({video:{...r.rows[0],id:String(r.rows[0].id),ownerName:req.user.display_name,likes:0,commentCount:0}});
  } catch(e) { fs.unlink(req.file.path,()=>{}); throw e; }
}));
app.post('/api/videos/:id/like', auth, asyncRoute(async (req,res) => {
  const id=req.params.id;if(!validId(id))return res.status(400).json({error:'Ungültiges Video.'});
  const exists=await pool.query('SELECT id FROM videos WHERE id=$1',[id]);if(!exists.rowCount)return res.status(404).json({error:'Video nicht gefunden.'});
  const prior=await pool.query('SELECT 1 FROM likes WHERE user_id=$1 AND video_id=$2',[req.user.id,id]);
  if(prior.rowCount)await pool.query('DELETE FROM likes WHERE user_id=$1 AND video_id=$2',[req.user.id,id]);else await pool.query('INSERT INTO likes(user_id,video_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.user.id,id]);
  const n=await pool.query('SELECT COUNT(*)::int AS n FROM likes WHERE video_id=$1',[id]);res.json({likes:n.rows[0].n,liked:!prior.rowCount});
}));
app.get('/api/videos/:id/comments', asyncRoute(async (req,res) => {
  if(!validId(req.params.id))return res.status(400).json({error:'Ungültige Video-ID.'});
  const r=await pool.query('SELECT c.id,c.text,c.created_at,u.display_name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.video_id=$1 AND u.disabled=FALSE ORDER BY c.created_at ASC LIMIT 200',[req.params.id]);res.json({comments:r.rows.map(c=>({id:String(c.id),text:c.text,createdAt:c.created_at,displayName:c.display_name}))});
}));
app.post('/api/videos/:id/comments', auth, asyncRoute(async (req,res) => {
  if(!validId(req.params.id))return res.status(400).json({error:'Ungültige Video-ID.'});
  const text=String(req.body?.text||'').trim();if(!text||text.length>500)return res.status(400).json({error:'Kommentar muss 1–500 Zeichen haben.'});
  const v=await pool.query('SELECT id FROM videos WHERE id=$1',[req.params.id]);if(!v.rowCount)return res.status(404).json({error:'Video nicht gefunden.'});
  const r=await pool.query('INSERT INTO comments(user_id,video_id,text) VALUES($1,$2,$3) RETURNING id,text,created_at',[req.user.id,req.params.id,text]);res.status(201).json({comment:{...r.rows[0],id:String(r.rows[0].id),displayName:req.user.display_name}});
}));
app.get('/api/members', auth, asyncRoute(async (req,res) => {
  const r=await pool.query(`SELECT u.id,u.username,u.display_name,u.avatar,u.role,EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=$1 AND f.followed_id=u.id) AS is_following FROM users u WHERE u.id<>$1 AND u.disabled=FALSE ORDER BY u.created_at DESC LIMIT 200`,[req.user.id]);res.json({members:r.rows.map(u=>({...publicUser(u),isFollowing:u.is_following}))});
}));
app.post('/api/follow/:id', auth, asyncRoute(async (req,res) => {
  if(!validId(req.params.id))return res.status(400).json({error:'Ungültige Mitglieder-ID.'});
  if(String(req.user.id)===String(req.params.id))return res.status(400).json({error:'Du kannst dir nicht selbst folgen.'});
  const target=await pool.query('SELECT id FROM users WHERE id=$1 AND disabled=FALSE',[req.params.id]);if(!target.rowCount)return res.status(404).json({error:'Mitglied nicht gefunden.'});
  const prior=await pool.query('SELECT 1 FROM follows WHERE follower_id=$1 AND followed_id=$2',[req.user.id,req.params.id]);if(prior.rowCount)await pool.query('DELETE FROM follows WHERE follower_id=$1 AND followed_id=$2',[req.user.id,req.params.id]);else await pool.query('INSERT INTO follows(follower_id,followed_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.user.id,req.params.id]);res.json({following:!prior.rowCount});
}));
app.get('/api/friends', auth, asyncRoute(async (req,res) => {
  const r=await pool.query(`SELECT u.id,u.username,u.display_name,u.bio,u.avatar,u.role FROM users u JOIN follows a ON a.followed_id=u.id AND a.follower_id=$1 JOIN follows b ON b.follower_id=u.id AND b.followed_id=$1 WHERE u.disabled=FALSE ORDER BY u.display_name`,[req.user.id]);res.json({friends:r.rows.map(publicUser)});
}));
app.get('/api/messages/:id', auth, asyncRoute(async (req,res) => {
  if(!validId(req.params.id))return res.status(400).json({error:'Ungültige Mitglieder-ID.'});
  const id=req.params.id;const r=await pool.query(`SELECT m.id,m.from_id,m.to_id,m.text,m.created_at,u.display_name FROM messages m JOIN users u ON u.id=m.from_id WHERE ((m.from_id=$1 AND m.to_id=$2) OR (m.from_id=$2 AND m.to_id=$1)) ORDER BY m.created_at ASC LIMIT 300`,[req.user.id,id]);res.json({messages:r.rows.map(m=>({id:String(m.id),fromId:String(m.from_id),toId:String(m.to_id),fromName:m.display_name,text:m.text,time:new Date(m.created_at).toLocaleString('de-DE')}))});
}));
app.post('/api/messages/:id', auth, asyncRoute(async (req,res) => {
  if(!validId(req.params.id))return res.status(400).json({error:'Ungültige Mitglieder-ID.'});
  const text=String(req.body?.text||'').trim();if(!text||text.length>1000)return res.status(400).json({error:'Nachricht muss 1–1000 Zeichen haben.'});if(String(req.params.id)===String(req.user.id))return res.status(400).json({error:'Du kannst dir selbst keine Nachricht senden.'});
  const target=await pool.query('SELECT id FROM users WHERE id=$1 AND disabled=FALSE',[req.params.id]);if(!target.rowCount)return res.status(404).json({error:'Empfänger nicht gefunden.'});
  const r=await pool.query('INSERT INTO messages(from_id,to_id,text) VALUES($1,$2,$3) RETURNING id,from_id,to_id,text,created_at',[req.user.id,req.params.id,text]);const m=r.rows[0];const payload={id:String(m.id),fromId:String(m.from_id),toId:String(m.to_id),fromName:req.user.display_name,text:m.text,time:new Date(m.created_at).toLocaleString('de-DE')};io.to('user:'+String(m.to_id)).emit('private message',payload);io.to('user:'+String(m.from_id)).emit('private message',payload);res.status(201).json({message:payload});
}));
app.get('/api/chat/public', auth, asyncRoute(async (_req,res) => {
  const r=await pool.query('SELECT m.id,m.user_id,m.text,m.created_at,u.display_name FROM public_messages m JOIN users u ON u.id=m.user_id WHERE u.disabled=FALSE ORDER BY m.created_at DESC LIMIT 100');res.json({messages:r.rows.reverse().map(m=>({id:String(m.id),fromId:String(m.user_id),fromName:m.display_name,text:m.text,time:new Date(m.created_at).toLocaleString('de-DE')}))});
}));
app.get('/api/admin', auth, admin, asyncRoute(async (_req,res) => {
  const [users,videos]=await Promise.all([pool.query('SELECT id,username,display_name,role,disabled,created_at FROM users ORDER BY created_at DESC'),pool.query('SELECT id,title,user_id,created_at FROM videos ORDER BY created_at DESC')]);res.json({users:users.rows.map(u=>({id:String(u.id),username:u.username,displayName:u.display_name,role:u.role,disabled:u.disabled,createdAt:u.created_at})),videos:videos.rows.map(v=>({id:String(v.id),title:v.title,userId:String(v.user_id),createdAt:v.created_at}))});
}));
app.delete('/api/admin/users/:id', auth, admin, asyncRoute(async (req,res) => {
  if(!validId(req.params.id))return res.status(400).json({error:'Ungültige Mitglieder-ID.'});
  if(String(req.user.id)===String(req.params.id))return res.status(400).json({error:'Du kannst dein eigenes Admin-Konto nicht sperren.'});
  const r=await pool.query("UPDATE users SET disabled=TRUE WHERE id=$1 AND role<>'admin' RETURNING id",[req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Konto nicht gefunden oder Admin-Konten können nicht gesperrt werden.'});io.in('user:'+String(r.rows[0].id)).disconnectSockets(true);res.json({ok:true});
}));

io.use(async (socket,next) => {
  try {const raw=socket.handshake.auth?.token;if(!raw)return next(new Error('Anmeldung erforderlich'));const p=jwt.verify(raw,JWT_SECRET,{issuer:'gametika'});const r=await pool.query('SELECT id,username,display_name,disabled,token_version FROM users WHERE id=$1',[p.id]);if(!r.rowCount||r.rows[0].disabled||Number(p.tv||0)!==Number(r.rows[0].token_version||0))return next(new Error('Sitzung ungültig'));socket.user={...r.rows[0],id:String(r.rows[0].id)};next();}catch(_e){next(new Error('Sitzung ungültig'));}
});
io.on('connection', socket => {
  socket.join('user:'+socket.user.id);
  let lastPublicMessageAt = 0;
  socket.on('public message', async payload => {
    try {
      const now = Date.now(); if (now - lastPublicMessageAt < 1200) return; lastPublicMessageAt = now;
      const active=await pool.query('SELECT disabled,token_version FROM users WHERE id=$1',[socket.user.id]);
      if(!active.rowCount||active.rows[0].disabled||Number(active.rows[0].token_version||0)!==Number(socket.user.token_version||0)){socket.disconnect(true);return;}
      const text=String(payload?.text||'').trim();if(!text||text.length>1000)return;const r=await pool.query('INSERT INTO public_messages(user_id,text) VALUES($1,$2) RETURNING id,created_at',[socket.user.id,text]);const m={id:String(r.rows[0].id),fromId:socket.user.id,fromName:socket.user.display_name,text,time:new Date(r.rows[0].created_at).toLocaleString('de-DE')};io.emit('public message',m);}catch(e){console.error('Public chat error:',e.message);}
  });
});
app.use((err,_req,res,_next) => {
  if(err instanceof multer.MulterError && err.code==='LIMIT_FILE_SIZE')return res.status(413).json({error:`Datei zu groß. Videos dürfen maximal 35 MB, Profilbilder maximal 3 MB haben.`});
  if(err instanceof multer.MulterError)return res.status(400).json({error:'Upload fehlgeschlagen: '+err.message});
  if(err.message && /Nur MP4|Profilbild muss/.test(err.message))return res.status(400).json({error:err.message});
  console.error(err.stack||err);res.status(500).json({error:'Interner Serverfehler. Bitte später erneut versuchen.'});
});
initDb().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`GAMETIKA API listening on ${PORT}; max video ${MAX_VIDEO_BYTES} bytes`))).catch(err=>{console.error('Database startup failed:',err);process.exit(1);});
process.on('SIGTERM',()=>server.close(()=>pool.end(()=>process.exit(0))));
