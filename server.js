// 物料项目号工具 — 数据服务（GitHub API 后端）
// 数据文件: items.json（存在 eastseao/xmh 仓库 main 分支）
const http = require("http");
const { execFile } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = 3457;
const ROOT = __dirname;
const OWNER = "eastseao";
const REPO = "xmh";
const BRANCH = "main";
const FILE = "items.json";
const GH = "C:\\Users\\Administrator\\.local\\bin\\gh.exe";
const ACCESS_PASSWORD = process.env.XMH_PASSWORD || "666888";
const SESSION_TTL = 7 * 24 * 3600 * 1000; // 7 天免登录
const sessions = new Map(); // token -> expiresAt
const loginFails = new Map(); // ip -> { count, until }

function gh(args) {
  return new Promise((resolve, reject) => {
    execFile(GH, args, { maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve(stdout);
    });
  });
}

// ---- GitHub 内容读写（走 gh CLI，token 不出服务端）----
async function loadItems() {
  try {
    const out = await gh([
      "api", `repos/${OWNER}/${REPO}/contents/${FILE}?ref=${BRANCH}`,
      "--jq", ".content"
    ]);
    const b64 = out.replace(/\s+/g, "");
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch (e) {
    if (String(e.message).includes("404")) return { items: [] };
    throw e;
  }
}

async function saveItems(data) {
  let sha;
  try {
    const out = await gh([
      "api", `repos/${OWNER}/${REPO}/contents/${FILE}?ref=${BRANCH}`,
      "--jq", ".sha"
    ]);
    sha = out.trim();
  } catch (e) {
    sha = null; // 文件不存在，新建
  }
  const content = Buffer.from(JSON.stringify(data, null, 2), "utf8").toString("base64");
  await gh([
    "api", `repos/${OWNER}/${REPO}/contents/${FILE}`,
    "-X", "PUT",
    "-f", `message=add ${data.items[0]?.code || "item"} ${new Date().toISOString().slice(0, 16).replace("T", " ")}`,
    "-f", `content=${content}`,
    "-f", `branch=${BRANCH}`,
    ...(sha ? ["-f", `sha=${sha}`] : []),
  ]);
}

// ---- 访问密码 / 会话（同 prompt 库）----
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  raw.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function isAuthed(req) {
  const token = parseCookies(req).token;
  if (!token || !sessions.has(token)) return false;
  if (Date.now() > sessions.get(token)) { sessions.delete(token); return false; }
  return true;
}

function unauthorized(res) {
  gate(res);
}

function gate(res) {
  res.writeHead(401, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: "unauthorized" }));
}

function clientKey(req) {
  return (req.headers["cf-connecting-ip"] || req.socket.remoteAddress || "unknown").toString();
}

async function handleLogin(req, res) {
  const ip = clientKey(req);
  const st = loginFails.get(ip);
  if (st && st.until > Date.now()) {
    const wait = Math.ceil((st.until - Date.now()) / 1000);
    res.writeHead(429, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ error: `尝试次数过多，请 ${wait} 秒后再试` }));
    return;
  }
  const p = await readBody(req);
  if (String(p.password || "") !== ACCESS_PASSWORD) {
    const cur = st && st.until > Date.now() ? st : { count: 0, until: 0 };
    cur.count += 1;
    if (cur.count >= 5) { cur.until = Date.now() + 10 * 60 * 1000; cur.count = 0; }
    loginFails.set(ip, cur);
    res.writeHead(401, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ error: "密码错误" }));
    return;
  }
  loginFails.delete(ip);
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, Date.now() + SESSION_TTL);
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Set-Cookie": `token=${token}; HttpOnly; Path=/; Max-Age=${Math.floor(SESSION_TTL / 1000)}; SameSite=Lax`,
  });
  res.end(JSON.stringify({ ok: true }));
}

// ---- 解析规则：截取前八位数字为项目号，剩余为物料名称 ----
function parseInput(raw) {
  const text = String(raw || "").trim();
  if (!text) return { error: "请输入内容" };
  // 取前 8 位连续数字作为项目号（允许前后有任意字符）
  const m = text.match(/\d{8}/);
  if (!m) return { error: "未找到 8 位数字项目号" };
  const code = m[0];
  const start = m.index;
  const end = m.index + 8;
  // 名称 = 去掉项目号后，剩余部分拼起来，去掉首尾分隔符
  let name = (text.slice(0, start) + " " + text.slice(end)).trim();
  name = name.replace(/^[\s\-_—–·.。,，:：;；/\\|]+|[\s\-_—–·.。,，:：;；/\\|]+$/g, "");
  return { code, name: name || "(未识别到名称)" };
}

// ---- 简易路由 ----
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === "/api/login" && req.method === "POST") {
    try { await handleLogin(req, res); } catch (e) { api500(res, e); }
    return;
  }

  if (url.pathname === "/api/health") {
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ ok: true, time: new Date().toISOString() }));
    return;
  }

  if (url.pathname.startsWith("/api/") && !isAuthed(req)) {
    return unauthorized(res);
  }

  if (url.pathname === "/api/items" && req.method === "GET") {
    try {
      const data = await loadItems();
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(data));
    } catch (e) { api500(res, e); }
    return;
  }

  if (url.pathname === "/api/items" && req.method === "POST") {
    try {
      const p = await readBody(req);
      const raw = String(p.raw || "");
      const parsed = parseInput(raw);
      if (parsed.error) return badRequest(res, parsed.error);
      const data = await loadItems();
      const now = Date.now();
      const item = {
        id: now.toString(36) + Math.random().toString(36).slice(2, 6),
        code: parsed.code,
        name: parsed.name,
        raw: raw.slice(0, 500),
        createdAt: now,
      };
      // 同项目号去重：覆盖旧记录（保留最新）
      data.items = data.items.filter(x => x.code !== parsed.code);
      data.items.unshift(item);
      await saveItems(data);
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true, item }));
    } catch (e) { api500(res, e); }
    return;
  }

  if (url.pathname.startsWith("/api/items/") && req.method === "DELETE") {
    try {
      const id = decodeURIComponent(url.pathname.split("/")[3]);
      const data = await loadItems();
      const idx = data.items.findIndex(x => x.id === id);
      if (idx === -1) return notFound(res);
      data.items.splice(idx, 1);
      await saveItems(data);
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true }));
    } catch (e) { api500(res, e); }
    return;
  }

  if (url.pathname === "/api/logout" && req.method === "POST") {
    const token = parseCookies(req).token;
    if (token) sessions.delete(token);
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": "token=; HttpOnly; Path=/; Max-Age=0",
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  serveStatic(req, res, url.pathname);
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = "";
    req.on("data", c => buf += c);
    req.on("end", () => {
      try { resolve(buf ? JSON.parse(buf) : {}); }
      catch { reject(new Error("invalid JSON")); }
    });
    req.on("error", reject);
  });
}

function badRequest(res, msg) {
  res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: msg }));
}

function notFound(res) {
  res.writeHead(404, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: "not found" }));
}

function api500(res, e) {
  console.error(`[api] ${e.message}`);
  res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: e.message }));
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function serveStatic(req, res, pathname) {
  if (pathname === "/") pathname = "/index.html";
  const file = path.normalize(path.join(ROOT, "public", pathname));
  if (!file.startsWith(path.join(ROOT, "public"))) { res.writeHead(403); res.end(); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not Found"); return; }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(data);
  });
}

server.listen(PORT, () => {
  console.log(`物料项目号工具已启动: http://localhost:${PORT}`);
  console.log(`数据后端: github.com/${OWNER}/${REPO} (${FILE} @ ${BRANCH})`);
});
