const Database = require("better-sqlite3");
const path = require("path");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "smart_electro.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

function addColumn(table, column, type) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(x => x.name);
  if (!cols.includes(column)) db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`).run();
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT DEFAULT '', mobile TEXT UNIQUE, email TEXT DEFAULT '',
 password TEXT NOT NULL, address TEXT DEFAULT '', lat REAL, lng REAL, role TEXT NOT NULL DEFAULT 'customer',
 skills TEXT DEFAULT '', experience TEXT DEFAULT '', profile_photo TEXT DEFAULT '', licence_photo TEXT DEFAULT '',
 aadhaar_number TEXT DEFAULT '', aadhaar_front TEXT DEFAULT '', aadhaar_back TEXT DEFAULT '', aadhaar_otp_verified INTEGER DEFAULT 0, verified INTEGER DEFAULT 0,
 available INTEGER DEFAULT 1, rating REAL DEFAULT 0, jobs_completed INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS jobs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL, category TEXT NOT NULL, service TEXT NOT NULL,
 description TEXT NOT NULL, quantity TEXT DEFAULT '', photo TEXT DEFAULT '', lat REAL, lng REAL, address TEXT DEFAULT '',
 preferred_date TEXT DEFAULT '', preferred_time TEXT DEFAULT '', emergency INTEGER DEFAULT 0, status TEXT DEFAULT 'Request Received',
 assigned_id INTEGER, final_amount REAL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(customer_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS job_offers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, provider_id INTEGER NOT NULL, status TEXT DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(job_id, provider_id), FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
 FOREIGN KEY(provider_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS quotations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, contractor_id INTEGER NOT NULL, amount REAL DEFAULT 0,
 material_cost REAL DEFAULT 0, labour_cost REAL DEFAULT 0, gst REAL DEFAULT 0, completion_days INTEGER DEFAULT 0,
 terms TEXT DEFAULT '', pdf TEXT DEFAULT '', status TEXT DEFAULT 'submitted', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE, FOREIGN KEY(contractor_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, customer_id INTEGER NOT NULL, amount REAL DEFAULT 0,
 method TEXT DEFAULT 'Cash', status TEXT DEFAULT 'paid', transaction_id TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS reviews (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL,
 rating INTEGER NOT NULL, review TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS complaints (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER, user_id INTEGER NOT NULL, message TEXT DEFAULT '',
 status TEXT DEFAULT 'open', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT DEFAULT 'info', title TEXT NOT NULL, message TEXT DEFAULT '',
 read INTEGER DEFAULT 0, job_id INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS job_views (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, viewer_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(job_id, viewer_id), FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE, FOREIGN KEY(viewer_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS work_posts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, provider_id INTEGER NOT NULL, caption TEXT DEFAULT '', photo TEXT NOT NULL, approval_status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE, FOREIGN KEY(provider_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS post_likes (
 id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(post_id,user_id),
 FOREIGN KEY(post_id) REFERENCES work_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS post_comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, comment TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(post_id) REFERENCES work_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS post_saves (
 id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(post_id,user_id),
 FOREIGN KEY(post_id) REFERENCES work_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY, value TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL, sender_id INTEGER NOT NULL, receiver_id INTEGER NOT NULL,
 message TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE, FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS invoices (
 id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL UNIQUE, invoice_no TEXT NOT NULL, amount REAL DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
);

`);

for (const [t,c,type] of [
 ["users","profile_photo","TEXT DEFAULT ''"],["users","licence_photo","TEXT DEFAULT ''"],["users","skills","TEXT DEFAULT ''"],
 ["users","experience","TEXT DEFAULT ''"],["users","aadhaar_number","TEXT DEFAULT ''"],["users","aadhaar_front","TEXT DEFAULT ''"],
 ["users","aadhaar_back","TEXT DEFAULT ''"],["users","aadhaar_otp_verified","INTEGER DEFAULT 0"],["users","available","INTEGER DEFAULT 1"],["users","rating","REAL DEFAULT 0"],
 ["users","jobs_completed","INTEGER DEFAULT 0"],["jobs","assigned_id","INTEGER"],["jobs","final_amount","REAL DEFAULT 0"],
 ["jobs","status","TEXT DEFAULT 'Request Received'"],["quotations","status","TEXT DEFAULT 'submitted'"],["jobs","completion_approval","TEXT DEFAULT 'pending'"],["jobs","completion_rejection_reason","TEXT DEFAULT ''"],["work_posts","approval_status","TEXT DEFAULT 'pending'"]
]) addColumn(t,c,type);

const crypto = require("crypto");
const ADMIN_MOBILE = process.env.ADMIN_MOBILE;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const admin = db.prepare("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").get();
db.prepare("INSERT INTO settings(key,value) VALUES('approval_mode','manual') ON CONFLICT(key) DO NOTHING").run();
db.prepare("INSERT INTO settings(key,value) VALUES('commission_rate','2') ON CONFLICT(key) DO NOTHING").run();
db.prepare("INSERT INTO settings(key,value) VALUES('adsense_client','') ON CONFLICT(key) DO NOTHING").run();
db.prepare("INSERT INTO settings(key,value) VALUES('adsense_slot','') ON CONFLICT(key) DO NOTHING").run();
if (ADMIN_MOBILE && ADMIN_PASSWORD) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(ADMIN_PASSWORD, salt, 64).toString("hex");
  const password = "scrypt$" + salt + "$" + hash;
  if (admin) {
    db.prepare("UPDATE users SET mobile=?, password=?, email=? WHERE id=?").run(ADMIN_MOBILE, password, "admin@smartelectro.local", admin.id);
  } else {
    db.prepare("INSERT INTO users(name,mobile,email,password,role,verified,available) VALUES(?,?,?,?,?,?,?)").run("Smart Electro Admin", ADMIN_MOBILE, "admin@smartelectro.local", password, "admin", 1, 1);
  }
}
module.exports = db;
