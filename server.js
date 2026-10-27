// Máy chủ Bảng kê - chỉ dùng thư viện có sẵn của Node.js (không cần npm install)
// Chạy:  node server.js     Mở:  http://localhost:3000
// Mật khẩu mặc định 11101956, đổi bằng biến môi trường BANGKE_PASS.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const PASS = String(process.env.BANGKE_PASS || '11101956');
const MAX_UPLOAD = 100 * 1024 * 1024;           // 100 MB / file
const SESSION_MS = 12 * 3600 * 1000;            // đăng nhập có hiệu lực 12 giờ
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data'), FILES = path.join(DATA, 'files'), IDX = path.join(DATA, 'index.json');
fs.mkdirSync(FILES, { recursive: true });
let idx = []; try { idx = JSON.parse(fs.readFileSync(IDX, 'utf8')); } catch (e) {}
const persist = () => fs.writeFileSync(IDX, JSON.stringify(idx));
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const passOk = p => crypto.timingSafeEqual(sha(p), sha(PASS));
const sessions = new Map(), fails = new Map();

const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const token = req => { const m = (req.headers.cookie || '').match(/(?:^|;\s*)bk=([a-f0-9]{64})/); return m && m[1]; };
const authed = req => { const t = token(req), e = t && sessions.get(t); if (e && e > Date.now()) return true; if (t) sessions.delete(t); return false; };
const json = (res, code, obj, headers = {}) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(b);
};
const readBody = (req, limit) => new Promise((resolve, reject) => {
  const chunks = []; let n = 0;
  req.on('data', c => { n += c.length; if (n > limit) { reject(new Error('Tệp quá lớn')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname;
  try {
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    if (p === '/api/login' && req.method === 'POST') {
      const key = ip(req), f = fails.get(key) || { n: 0, until: 0 };
      if (f.until > Date.now()) return json(res, 429, { error: 'Nhập sai nhiều lần, thử lại sau ít phút.' });
      let body = {}; try { body = JSON.parse((await readBody(req, 4096)).toString() || '{}'); } catch (e) {}
      if (!passOk(body.pass || '')) {
        f.n++; if (f.n >= 5) { f.until = Date.now() + 10 * 60 * 1000; f.n = 0; }
        fails.set(key, f); return json(res, 401, { error: 'Mật khẩu không đúng.' });
      }
      fails.delete(key);
      const t = crypto.randomBytes(32).toString('hex'); sessions.set(t, Date.now() + SESSION_MS);
      const secure = (req.headers['x-forwarded-proto'] === 'https') ? '; Secure' : '';
      return json(res, 200, { ok: true }, { 'Set-Cookie': `bk=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
    }
    if (p === '/api/logout' && req.method === 'POST') { sessions.delete(token(req)); return json(res, 200, { ok: true }, { 'Set-Cookie': 'bk=; HttpOnly; Path=/; Max-Age=0' }); }
    if (!p.startsWith('/api/')) return json(res, 404, { error: 'Không tìm thấy' });
    if (!authed(req)) return json(res, 401, { error: 'Cần đăng nhập' });
    if (p === '/api/me') return json(res, 200, { ok: true });
    if (p === '/api/kho' && req.method === 'GET') return json(res, 200, idx);
    if (p === '/api/kho' && req.method === 'POST') {
      const kind = url.searchParams.get('kind');
      if (!['sk', 'dt', 'hd', 'sq', 'st', 'bk'].includes(kind)) return json(res, 400, { error: 'Loại file không hợp lệ' });
      const buf = await readBody(req, MAX_UPLOAD);
      if (!buf.length) return json(res, 400, { error: 'File rỗng' });
      const id = kind + '_' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
      fs.writeFileSync(path.join(FILES, id), buf);
      const it = { id, kind, name: String(url.searchParams.get('name') || id).slice(0, 200), size: buf.length,
        month: String(url.searchParams.get('month') || '').slice(0, 40), tag: String(url.searchParams.get('tag') || '').slice(0, 40), at: Date.now() };
      idx.push(it); persist(); return json(res, 200, it);
    }
    const m = p.match(/^\/api\/kho\/([a-z]{2}_[a-z0-9]+)(\/file)?$/), it = m && idx.find(x => x.id === m[1]);
    if (m && !it) return json(res, 404, { error: 'Không có file' });
    if (m && m[2] && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store',
        'Content-Disposition': "attachment; filename*=UTF-8''" + encodeURIComponent(it.name) });
      return fs.createReadStream(path.join(FILES, it.id)).pipe(res);
    }
    if (m && !m[2] && req.method === 'DELETE') {
      try { fs.unlinkSync(path.join(FILES, it.id)); } catch (e) {}
      idx = idx.filter(x => x.id !== it.id); persist(); return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: 'Không tìm thấy' });
  } catch (e) { if (!res.headersSent) json(res, 500, { error: e.message || 'Lỗi máy chủ' }); }
});
setInterval(() => { const now = Date.now(); for (const [t, e] of sessions) if (e < now) sessions.delete(t); }, 3600 * 1000).unref();
server.listen(PORT, () => console.log('Bảng kê đang chạy tại http://localhost:' + PORT + '  (mật khẩu: ' + (process.env.BANGKE_PASS ? 'đã đặt riêng' : 'mặc định') + ')'));
