// คลังสคริป - เซิร์ฟเวอร์ (Node 18+ ไม่ต้องติดตั้งแพ็กเกจเพิ่ม)
// รัน:  node server.js
// ตัวแปรเสริม: PORT, ACCESS_CODE (รหัสเข้าเว็บ), DATA_DIR (โฟลเดอร์เก็บข้อมูล ต้องเป็นดิสก์ถาวร)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const ACCESS = (process.env.ACCESS_CODE || 'Augjdlohoo8yek2').trim();
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DIR, 'vault.json');
fs.mkdirSync(DIR, { recursive: true });
let db = {};
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) {}
const save = () => { const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, FILE); };

// เนื้อหาแต่ละรายการถูกเข้ารหัส AES-256-GCM ด้วยรหัสผ่านของรายการนั้น (เซิร์ฟเวอร์อ่านเนื้อหาไม่ได้ถ้าไม่มีรหัส)
const derive = (pw, salt) => crypto.scryptSync(pw, salt, 64);
function seal(pw, payload, salt) {
  salt = salt || crypto.randomBytes(16);
  const k = derive(pw, salt), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', k.subarray(0, 32), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(payload), 'utf8'), c.final()]);
  return { salt: salt.toString('base64'), check: k.subarray(32).toString('base64'), iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64') };
}
function unseal(e, pw) {
  const k = derive(pw, Buffer.from(e.salt, 'base64'));
  if (!crypto.timingSafeEqual(Buffer.from(e.check, 'base64'), k.subarray(32))) return null;
  const d = crypto.createDecipheriv('aes-256-gcm', k.subarray(0, 32), Buffer.from(e.iv, 'base64'));
  d.setAuthTag(Buffer.from(e.tag, 'base64'));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(e.ct, 'base64')), d.final()]).toString('utf8'));
}

// กันเดารหัส: ผิด 5 ครั้งรอ 1 นาที
const fails = {};
const isLocked = id => { const f = fails[id]; return f && f.n >= 5 && Date.now() - f.t < 60000; };
const markBad = id => { const f = fails[id]; fails[id] = { n: f && Date.now() - f.t < 600000 ? f.n + 1 : 1, t: Date.now() }; };

const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(obj)); };

function route(url, b, res) {
  const id = b.id;
  if (url === '/api/list') {
    const q = String(b.q || '').toLowerCase();
    const items = Object.entries(db).filter(([, v]) => !q || v.name.toLowerCase().includes(q))
      .map(([k, v]) => ({ id: k, name: v.name, updated: v.updated })).sort((x, y) => y.updated - x.updated).slice(0, 100);
    return send(res, 200, { items });
  }
  if (url === '/api/create') {
    const name = String(b.name || '').trim().slice(0, 200), pw = String(b.password || '');
    if (!name || pw.length < 4) return send(res, 400, { error: 'ต้องมีชื่อ และรหัสผ่านอย่างน้อย 4 ตัว' });
    const nid = crypto.randomBytes(9).toString('hex');
    db[nid] = { name, updated: Date.now(), ...seal(pw, { text: b.text || '', files: b.files || [] }) };
    save();
    return send(res, 200, { id: nid });
  }
  const e = db[id];
  if (!e) return send(res, 404, { error: 'ไม่พบรายการนี้' });
  if (isLocked(id)) return send(res, 429, { error: 'ใส่รหัสผิดหลายครั้ง รอ 1 นาทีแล้วลองใหม่' });
  const pw = String(b.password || '');
  const p = unseal(e, pw);
  if (!p) { markBad(id); return send(res, 403, { error: 'รหัสผ่านไม่ถูกต้อง' }); }
  delete fails[id];
  if (url === '/api/open') return send(res, 200, { name: e.name, text: p.text, files: p.files || [] });
  if (url === '/api/update') {
    const name = String(b.name || e.name).trim().slice(0, 200);
    const npw = b.newPassword && String(b.newPassword).length >= 4 ? String(b.newPassword) : null;
    db[id] = { name, updated: Date.now(), ...seal(npw || pw, { text: b.text || '', files: b.files || [] }, npw ? undefined : Buffer.from(e.salt, 'base64')) };
    save();
    return send(res, 200, { ok: true });
  }
  if (url === '/api/delete') { delete db[id]; save(); return send(res, 200, { ok: true }); }
  send(res, 404, { error: 'ไม่รู้จักคำสั่ง' });
}

http.createServer((req, res) => {
  if (req.method === 'GET') {
    if (req.url === '/' || req.url.startsWith('/?') || req.url === '/index.html') {
      return fs.readFile(path.join(__dirname, 'index.html'), (err, d) => {
        if (err) { res.writeHead(404); return res.end('index.html not found'); }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(d);
      });
    }
    res.writeHead(404); return res.end();
  }
  if (req.method !== 'POST' || !req.url.startsWith('/api/')) { res.writeHead(404); return res.end(); }
  let size = 0; const chunks = [];
  req.on('data', c => { size += c.length; if (size > 12e6) req.destroy(); else chunks.push(c); });
  req.on('end', () => {
    try {
      if (String(req.headers['x-access'] || '').trim() !== ACCESS) return send(res, 401, { error: 'รหัสเข้าใช้งานไม่ถูกต้อง' });
      route(req.url, JSON.parse(Buffer.concat(chunks).toString() || '{}'), res);
    } catch (e) { send(res, 400, { error: 'คำขอไม่ถูกต้อง' }); }
  });
}).listen(PORT, () => console.log('คลังสคริปรันที่พอร์ต ' + PORT + ' · ข้อมูลอยู่ที่ ' + FILE));
