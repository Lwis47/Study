const path = require("node:path");
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const { rateLimit } = require("express-rate-limit");
const { pool, initDatabase } = require("./db");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const SESSION_SECRET = process.env.SESSION_SECRET;
const PgSession = connectPgSimple(session);
const allowedCategories = new Set([
  "Linux & Networking", "Python & Programming", "Web Development",
  "Databases & SQL", "Cybersecurity", "Operating Systems",
]);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const usernamePattern = /^[A-Za-z0-9_.-]{3,30}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be set to a random value with at least 32 characters");
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      ...helmet.contentSecurityPolicy.getDefaultDirectives(),
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "media-src": ["'self'"],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
    },
  },
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  name: "cypher.sid",
  secret: SESSION_SECRET,
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true, pruneSessionInterval: 60 }),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000, path: "/" },
}));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 240, standardHeaders: "draft-8", legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: "draft-8", legacyHeaders: false, message: { error: "Too many attempts. Try again in a few minutes." } });
app.use("/api", apiLimiter);

function httpError(status, message) { const error = new Error(message); error.status = status; return error; }
function text(value, max) { return typeof value === "string" ? value.trim().slice(0, max) : ""; }
function email(value) { return text(value, 254).toLowerCase(); }
function publicUser(row) {
  return {
    id: row.id, fullName: row.full_name, username: row.username, email: row.email,
    role: row.role, status: row.status, bio: row.bio,
    progress: row.progress || {}, createdAt: row.created_at, lastLoginAt: row.last_login_at,
  };
}
function sameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (!origin && process.env.NODE_ENV === "production") return res.status(403).json({ error: "Request origin is required." });
  if (origin) {
    try {
      if (new URL(origin).host !== req.get("host")) return res.status(403).json({ error: "Cross-origin request blocked." });
    } catch { return res.status(403).json({ error: "Invalid request origin." }); }
  }
  next();
}
async function requireAuth(req, res, next) {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Please log in." });
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.session.userId]);
    const user = result.rows[0];
    if (!user || user.status !== "active") {
      req.session.destroy(() => {});
      return res.status(401).json({ error: "This account is unavailable. Please contact an administrator." });
    }
    req.user = user;
    next();
  } catch (error) { next(error); }
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Administrator access required." });
  next();
}
const requireActiveAdmin = [requireAuth, requireAdmin];

app.get("/api/health", async (req, res, next) => {
  try { await pool.query("SELECT 1"); res.json({ status: "ok" }); }
  catch (error) { next(error); }
});

app.post("/api/auth/register", authLimiter, sameOrigin, async (req, res, next) => {
  try {
    const fullName = text(req.body.fullName, 120);
    const username = text(req.body.username, 30);
    const normalizedEmail = email(req.body.email);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (fullName.length < 2) throw httpError(400, "Enter your full name.");
    if (!usernamePattern.test(username)) throw httpError(400, "Username must be 3–30 characters using letters, numbers, dots, dashes, or underscores.");
    if (!emailPattern.test(normalizedEmail)) throw httpError(400, "Enter a valid email address.");
    if (password.length < 10 || password.length > 128) throw httpError(400, "Password must be between 10 and 128 characters.");
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (full_name, username, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING *",
      [fullName, username, normalizedEmail, passwordHash],
    );
    await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
    req.session.userId = result.rows[0].id;
    res.status(201).json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "That email or username is already registered." });
    next(error);
  }
});

app.post("/api/auth/login", authLimiter, sameOrigin, async (req, res, next) => {
  try {
    const identity = text(req.body.identity, 254).toLowerCase();
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const result = await pool.query("SELECT * FROM users WHERE LOWER(email) = $1 OR LOWER(username) = $1 LIMIT 1", [identity]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "The username/email or password is incorrect." });
    if (user.status !== "active") return res.status(403).json({ error: "This account is suspended. Contact an administrator." });
    await new Promise((resolve, reject) => req.session.regenerate((error) => error ? reject(error) : resolve()));
    req.session.userId = user.id;
    await pool.query("UPDATE users SET last_login_at = NOW() WHERE id = $1", [user.id]);
    res.json({ user: publicUser({ ...user, last_login_at: new Date() }) });
  } catch (error) { next(error); }
});

app.post("/api/auth/logout", sameOrigin, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("cypher.sid", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/" });
    res.status(204).end();
  });
});

app.get("/api/auth/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

app.patch("/api/account", sameOrigin, requireAuth, async (req, res, next) => {
  try {
    const fullName = text(req.body.fullName, 120);
    const username = text(req.body.username, 30);
    const normalizedEmail = email(req.body.email);
    const bio = text(req.body.bio, 240);
    if (fullName.length < 2) throw httpError(400, "Enter your full name.");
    if (!usernamePattern.test(username)) throw httpError(400, "Username must be 3–30 characters using letters, numbers, dots, dashes, or underscores.");
    if (!emailPattern.test(normalizedEmail)) throw httpError(400, "Enter a valid email address.");
    const result = await pool.query("UPDATE users SET full_name = $1, username = $2, email = $3, bio = $4 WHERE id = $5 RETURNING *", [fullName, username, normalizedEmail, bio, req.user.id]);
    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "That email or username is already in use." });
    next(error);
  }
});

app.patch("/api/account/password", sameOrigin, requireAuth, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (typeof newPassword !== "string" || newPassword.length < 10 || newPassword.length > 128) throw httpError(400, "New password must be between 10 and 128 characters.");
    if (typeof currentPassword !== "string" || !(await bcrypt.compare(currentPassword, req.user.password_hash))) throw httpError(400, "Current password is incorrect.");
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, req.user.id]);
    res.json({ message: "Password changed." });
  } catch (error) { next(error); }
});

app.delete("/api/account", sameOrigin, requireAuth, async (req, res, next) => {
  try {
    if (req.user.role === "admin") {
      const admins = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin' AND status = 'active'");
      if (admins.rows[0].count <= 1) throw httpError(409, "Create another active administrator before deleting this account.");
    }
    await pool.query("DELETE FROM users WHERE id = $1", [req.user.id]);
    req.session.destroy(() => {});
    res.status(204).end();
  } catch (error) { next(error); }
});

app.patch("/api/account/progress/:lessonId", sameOrigin, requireAuth, async (req, res, next) => {
  try {
    if (!/^[a-z0-9-]{1,60}$/.test(req.params.lessonId)) throw httpError(400, "Invalid lesson id.");
    const completed = req.body.completed === true;
    const result = await pool.query(
      "UPDATE users SET progress = jsonb_set(progress, ARRAY[$1]::text[], to_jsonb($2::boolean), true) WHERE id = $3 RETURNING progress",
      [req.params.lessonId, completed, req.user.id],
    );
    res.json({ progress: result.rows[0].progress });
  } catch (error) { next(error); }
});

app.get("/api/admin/users", ...requireActiveAdmin, async (req, res, next) => {
  try {
    const search = `%${text(req.query.q, 100).replace(/[\\%_]/g, (char) => `\\${char}`)}%`;
    const result = await pool.query(
      "SELECT * FROM users WHERE full_name ILIKE $1 OR username ILIKE $1 OR email ILIKE $1 OR role ILIKE $1 OR status ILIKE $1 ORDER BY created_at DESC LIMIT 500",
      [search],
    );
    res.json({ users: result.rows.map(publicUser) });
  } catch (error) { next(error); }
});

app.patch("/api/admin/users/:id", sameOrigin, ...requireActiveAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!uuidPattern.test(id)) throw httpError(404, "User not found.");
    const targetResult = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const target = targetResult.rows[0];
    if (!target) throw httpError(404, "User not found.");
    const fullName = text(req.body.fullName ?? target.full_name, 120);
    const username = text(req.body.username ?? target.username, 30);
    const normalizedEmail = email(req.body.email ?? target.email);
    const role = req.body.role ?? target.role;
    const status = req.body.status ?? target.status;
    const bio = text(req.body.bio ?? target.bio, 240);
    if (fullName.length < 2 || !usernamePattern.test(username) || !emailPattern.test(normalizedEmail)) throw httpError(400, "Provide a valid name, username, and email.");
    if (!['user', 'admin'].includes(role) || !['active', 'suspended'].includes(status)) throw httpError(400, "Invalid role or account status.");
    if (target.id === req.user.id && (role !== "admin" || status !== "active")) throw httpError(409, "You cannot remove your own active administrator access.");
    if (target.role === "admin" && target.status === "active" && (role !== "admin" || status !== "active")) {
      const admins = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role = 'admin' AND status = 'active'");
      if (admins.rows[0].count <= 1) throw httpError(409, "There must always be at least one active administrator.");
    }
    const result = await pool.query("UPDATE users SET full_name=$1, username=$2, email=$3, role=$4, status=$5, bio=$6 WHERE id=$7 RETURNING *", [fullName, username, normalizedEmail, role, status, bio, id]);
    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "That email or username is already in use." });
    next(error);
  }
});

app.patch("/api/admin/users/:id/password", sameOrigin, ...requireActiveAdmin, async (req, res, next) => {
  try {
    if (!uuidPattern.test(req.params.id)) throw httpError(404, "User not found.");
    const password = req.body.password;
    if (typeof password !== "string" || password.length < 10 || password.length > 128) throw httpError(400, "Password must be between 10 and 128 characters.");
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2 RETURNING id", [passwordHash, req.params.id]);
    if (!result.rowCount) throw httpError(404, "User not found.");
    res.json({ message: "Password updated." });
  } catch (error) { next(error); }
});

app.delete("/api/admin/users/:id", sameOrigin, ...requireActiveAdmin, async (req, res, next) => {
  try {
    if (!uuidPattern.test(req.params.id)) throw httpError(404, "User not found.");
    const result = await pool.query("SELECT role, status FROM users WHERE id=$1", [req.params.id]);
    if (!result.rowCount) throw httpError(404, "User not found.");
    if (req.params.id === req.user.id) throw httpError(409, "Use account settings to delete your own account, or ask another administrator.");
    if (result.rows[0].role === "admin" && result.rows[0].status === "active") {
      const admins = await pool.query("SELECT COUNT(*)::int AS count FROM users WHERE role='admin' AND status='active'");
      if (admins.rows[0].count <= 1) throw httpError(409, "There must always be at least one active administrator.");
    }
    await pool.query("DELETE FROM users WHERE id=$1", [req.params.id]);
    res.status(204).end();
  } catch (error) { next(error); }
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 12 * 1024 * 1024, files: 1, fields: 4 },
  fileFilter: (req, file, done) => {
    if (file.mimetype !== "application/pdf" || !file.originalname.toLowerCase().endsWith(".pdf")) return done(httpError(415, "Upload a PDF file."));
    done(null, true);
  },
});
app.post("/api/resources", sameOrigin, requireAuth, upload.single("file"), async (req, res, next) => {
  try {
    const title = text(req.body.title, 160);
    const category = text(req.body.category, 80);
    const description = text(req.body.description, 500);
    if (title.length < 3 || !allowedCategories.has(category) || description.length < 5) throw httpError(400, "Provide a title, valid category, and description.");
    if (!req.file || req.file.buffer.subarray(0, 5).toString("ascii") !== "%PDF-") throw httpError(415, "The uploaded file is not a valid PDF.");
    const result = await pool.query(
      "INSERT INTO resources (uploader_id,title,category,description,file_name,file_data) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,title,category,description,status,created_at",
      [req.user.id, title, category, description, path.basename(req.file.originalname).slice(0, 255), req.file.buffer],
    );
    res.status(201).json({ resource: result.rows[0] });
  } catch (error) { next(error); }
});

app.get("/api/resources", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT id,title,category,description,status,created_at FROM resources WHERE status='approved' ORDER BY created_at DESC LIMIT 200");
    res.json({ resources: result.rows });
  } catch (error) { next(error); }
});

app.get("/api/admin/resources", ...requireActiveAdmin, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT r.id,r.title,r.category,r.description,r.file_name,r.status,r.review_note,r.created_at,u.username AS uploader FROM resources r LEFT JOIN users u ON u.id=r.uploader_id ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 500");
    res.json({ resources: result.rows });
  } catch (error) { next(error); }
});

app.patch("/api/admin/resources/:id", sameOrigin, ...requireActiveAdmin, async (req, res, next) => {
  try {
    if (!uuidPattern.test(req.params.id)) throw httpError(404, "Resource not found.");
    const status = req.body.status;
    const reviewNote = text(req.body.reviewNote, 500);
    if (!['approved', 'rejected'].includes(status)) throw httpError(400, "Choose approve or reject.");
    const result = await pool.query("UPDATE resources SET status=$1, review_note=$2, reviewer_id=$3, reviewed_at=NOW() WHERE id=$4 RETURNING id,status", [status, reviewNote, req.user.id, req.params.id]);
    if (!result.rowCount) throw httpError(404, "Resource not found.");
    res.json({ resource: result.rows[0] });
  } catch (error) { next(error); }
});

app.get("/api/resources/:id/file", requireAuth, async (req, res, next) => {
  try {
    if (!uuidPattern.test(req.params.id)) throw httpError(404, "Resource not found.");
    const result = await pool.query("SELECT file_name,file_data,status FROM resources WHERE id=$1", [req.params.id]);
    const resource = result.rows[0];
    if (!resource) throw httpError(404, "Resource not found.");
    if (resource.status !== "approved" && req.user.role !== "admin") throw httpError(404, "Resource not found.");
    const fileName = resource.file_name.replace(/[\r\n"\\]/g, "_");
    res.set({ "Content-Type": "application/pdf", "Content-Disposition": `inline; filename="${fileName}"`, "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store" });
    res.send(resource.file_data);
  } catch (error) { next(error); }
});

// Never expose server configuration, database files, package manifests, or the admin bootstrap script.
app.use((req, res, next) => {
  if (/\/(?:server\.js|db\.js|package(?:-lock)?\.json|render\.yaml|\.env.*|scripts\/.*|node_modules\/.*|README.*|\.git.*)$/i.test(req.path)) return res.sendStatus(404);
  next();
});
app.use(express.static(__dirname, { dotfiles: "deny", index: "index.html", maxAge: process.env.NODE_ENV === "production" ? "1h" : 0 }));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.use("/api", (req, res) => res.status(404).json({ error: "API endpoint not found." }));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = Number(error.status) || (error instanceof multer.MulterError ? 400 : 500);
  if (status >= 500) console.error(error);
  res.status(status).json({ error: status >= 500 ? "The server could not complete that request." : error.message });
});

async function start() {
  await initDatabase();
  const server = app.listen(PORT, "0.0.0.0", () => console.log(`Cypher-School listening on port ${PORT}`));
  const shutdown = () => server.close(async () => { await pool.end(); process.exit(0); });
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (require.main === module) start().catch((error) => { console.error("Startup failed", error); process.exit(1); });

module.exports = { app, start };
