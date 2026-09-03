const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "SMART_ELECTRO_SECRET_2026_CHANGE_ME";
const ALLOWED_ROLES = ["customer","electrician","technician","engineer","contractor","solar","automation","admin"];
const PROVIDER_ROLES = ["electrician","technician","engineer","contractor","solar","automation"];
const JOB_STATUSES = ["Request Received","Accepted","On the Way","Arrived","Work Started","Work Completed","Admin Review Pending","Payment Pending","Payment Completed","Closed","Cancelled"];
const NEXT_STATUS = {"Accepted":"On the Way","On the Way":"Arrived","Arrived":"Work Started","Work Started":"Work Completed","Work Completed":"Admin Review Pending","Admin Review Pending":"Payment Pending","Payment Pending":"Payment Completed","Payment Completed":"Closed"};

app.disable("x-powered-by");
app.use(cors());
app.use(express.json({limit:"12mb"}));
app.use(express.urlencoded({extended:true,limit:"12mb"}));
app.use(express.static(path.join(__dirname,"../public")));

function token(u){ return jwt.sign({id:u.id,role:u.role},JWT_SECRET,{expiresIn:"30d"}); }
function hashPassword(password){
  const salt=crypto.randomBytes(16).toString("hex");
  const hash=crypto.scryptSync(password,salt,64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}
function verifyPassword(password,stored){
  if(!stored) return false;
  if(!stored.startsWith("scrypt$")) return stored===password; // migrate legacy accounts after successful login
  const [,salt,hex]=stored.split("$");
  try { const a=Buffer.from(hex,"hex"), b=crypto.scryptSync(password,salt,64); return a.length===b.length && crypto.timingSafeEqual(a,b); } catch { return false; }
}
function auth(req,res,next){
  try{
    const h=req.headers.authorization||"";
    if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Login required"});
    const p=jwt.verify(h.slice(7),JWT_SECRET);
    const u=db.prepare("SELECT id,role FROM users WHERE id=?").get(p.id);
    if(!u) return res.status(401).json({error:"User not found"});
    req.user=u; next();
  }catch(e){ return res.status(401).json({error:"Invalid or expired token"}); }
}
function role(...roles){ return (req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:"Access denied"}); }
function publicUser(id){
  return id ? (db.prepare(`SELECT id,name,mobile,email,address,lat,lng,role,skills,experience,profile_photo,verified,available,rating,jobs_completed,created_at FROM users WHERE id=?`).get(id)||null) : null;
}
function privateUserKyc(id){
  return id ? (db.prepare(`SELECT id,name,mobile,email,address,role,profile_photo,licence_photo,aadhaar_number,aadhaar_front,aadhaar_back,aadhaar_otp_verified,verified,available,rating,jobs_completed,created_at FROM users WHERE id=?`).get(id)||null) : null;
}

function fullJob(id){
  return db.prepare(`SELECT j.*,c.name customer_name,c.mobile customer_mobile,c.profile_photo customer_photo,c.aadhaar_otp_verified customer_kyc_verified,c.verified customer_verified,
    u.id electrician_id,u.name electrician_name,u.mobile electrician_mobile,u.role electrician_role,u.profile_photo electrician_photo,
    u.skills electrician_skills,u.experience electrician_experience,u.rating electrician_rating,u.verified electrician_verified,u.available electrician_available
    FROM jobs j LEFT JOIN users c ON c.id=j.customer_id LEFT JOIN users u ON u.id=j.assigned_id WHERE j.id=?`).get(id);
}
function providerCanSeeJob(j,user){ return user.role==="admin" || j.customer_id===user.id || j.assigned_id===user.id || (PROVIDER_ROLES.includes(user.role) && j.status==="Request Received"); }
function notify(userId,type,title,message,jobId=null){ if(!userId) return; db.prepare("INSERT INTO notifications(user_id,type,title,message,job_id) VALUES(?,?,?,?,?)").run(userId,type,title,message,jobId); }
function notifyNearbyProviders(job){
  const providers=db.prepare("SELECT id FROM users WHERE role IN ('electrician','technician','contractor','solar','automation') AND verified=1 AND available=1").all();
  for(const p of providers) notify(p.id,"job","New electrical job available",`New ${job.service} requirement #${job.id} is available. Open it to view the customer's problem photo and details.`,job.id);
}
function publicPost(id,userId=null){
  const p=db.prepare(`SELECT wp.*,u.name provider_name,u.role provider_role,u.profile_photo provider_photo,u.rating provider_rating,u.jobs_completed,
    (SELECT COUNT(*) FROM post_likes WHERE post_id=wp.id) likes,
    (SELECT COUNT(*) FROM post_comments WHERE post_id=wp.id) comments,
    (SELECT COUNT(*) FROM post_saves WHERE post_id=wp.id) saves
    FROM work_posts wp JOIN users u ON u.id=wp.provider_id WHERE wp.id=?`).get(id);
  if(!p) return null; p.liked=!!(userId&&db.prepare("SELECT id FROM post_likes WHERE post_id=? AND user_id=?").get(id,userId)); p.saved=!!(userId&&db.prepare("SELECT id FROM post_saves WHERE post_id=? AND user_id=?").get(id,userId)); return p;
}
function publicJob(j,user){
  if(!j) return j;
  const isAdmin=user?.role==="admin", isCustomer=user?.role==="customer";
  if(!isAdmin && !isCustomer){ delete j.customer_mobile; delete j.customer_verified; delete j.customer_kyc_verified; }
  return j;
}
function companySettings(){ return {logo:db.prepare("SELECT value FROM settings WHERE key='company_logo'").get()?.value||"",company_name:db.prepare("SELECT value FROM settings WHERE key='company_name'").get()?.value||"Shubhraj Energy Systems"}; }

app.get("/api/health",(req,res)=>res.json({ok:true,service:"Smart Electro",port:PORT}));

app.post("/api/auth/register",(req,res)=>{
  try{
    const b=req.body||{}, name=String(b.name||"").trim(), mobile=String(b.mobile||"").replace(/\s+/g,"").trim(), password=String(b.password||"");
    const roleValue=ALLOWED_ROLES.includes(b.role)&&b.role!=="admin"?b.role:"customer";
    if(!name||!/^[0-9]{10}$/.test(mobile)||password.length<6) return res.status(400).json({error:"Enter name, valid 10-digit mobile and password of at least 6 characters"});
    if(db.prepare("SELECT id FROM users WHERE mobile=?").get(mobile)) return res.status(409).json({error:"Mobile already registered"});
    const needsKyc = roleValue === "customer" || PROVIDER_ROLES.includes(roleValue);
    if(needsKyc){
      const aadhaar=String(b.aadhaar_number||"").replace(/\s/g,"");
      if(!/^\d{12}$/.test(aadhaar)) return res.status(400).json({error:"Valid 12-digit Aadhaar number is required"});
      if(!String(b.aadhaar_front||"").startsWith("data:image/") || !String(b.aadhaar_back||"").startsWith("data:image/")) return res.status(400).json({error:"Aadhaar front and back photos are compulsory"});
      if(b.aadhaar_otp_verified!==true && b.aadhaar_otp_verified!=="true") return res.status(400).json({error:"Aadhaar OTP verification is required before registration"});
    }
    const r=db.prepare(`INSERT INTO users(name,mobile,email,password,role,skills,experience,profile_photo,licence_photo,aadhaar_number,aadhaar_front,aadhaar_back,aadhaar_otp_verified,verified,available,address)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(name,mobile,String(b.email||"").trim(),hashPassword(password),roleValue,String(b.skills||""),String(b.experience||""),String(b.profile_photo||""),String(b.licence_photo||""),String(b.aadhaar_number||""),String(b.aadhaar_front||""),String(b.aadhaar_back||""),needsKyc?1:0,roleValue==="customer"?1:0,roleValue==="customer"?1:0,String(b.address||""));
    const u=publicUser(r.lastInsertRowid); if(needsKyc) notify(1,"kyc","New KYC submitted",`${u.name} submitted Aadhaar KYC documents for admin review.`);
    res.json({token:token(u),user:u,message:roleValue==="customer"?"Registration successful":"Registration submitted. Admin verification is required before provider jobs are enabled."});
  }catch(e){console.error(e);res.status(500).json({error:"Registration failed"});}
});
app.post("/api/auth/aadhaar-otp",(req,res)=>{
  const aadhaar=String(req.body.aadhaar_number||"").replace(/\s/g,"");
  if(!/^\d{12}$/.test(aadhaar)) return res.status(400).json({error:"Enter a valid 12-digit Aadhaar number"});
  // Demo/local mode only. Production must use an authorised UIDAI/KYC authentication provider.
  const otp=String(Math.floor(100000+Math.random()*900000));
  const expires=Date.now()+5*60*1000;
  global.__aadhaarOtp=global.__aadhaarOtp||new Map(); global.__aadhaarOtp.set(aadhaar,{otp,expires});
  console.log(`[SMART ELECTRO DEMO] Aadhaar OTP for ${aadhaar.slice(0,4)}******${aadhaar.slice(-2)}: ${otp}`);
  res.json({success:true,message:"Demo Aadhaar OTP generated. In production connect an authorised Aadhaar/KYC provider.",demo_otp:otp,expires_in:300});
});
app.post("/api/auth/aadhaar-verify-otp",(req,res)=>{
  const aadhaar=String(req.body.aadhaar_number||"").replace(/\s/g,""); const otp=String(req.body.otp||"");
  const rec=global.__aadhaarOtp?.get(aadhaar);
  if(!rec||Date.now()>rec.expires||rec.otp!==otp) return res.status(400).json({error:"Invalid or expired Aadhaar OTP"});
  global.__aadhaarOtp.delete(aadhaar); res.json({success:true,verified:true,message:"Aadhaar OTP verified (demo/local mode)"});
});

app.post("/api/auth/login",(req,res)=>{
  try{
    const mobile=String(req.body.mobile||"").replace(/\s+/g,"").trim(), password=String(req.body.password||"");
    const u=db.prepare("SELECT * FROM users WHERE mobile=?").get(mobile);
    if(!u||!verifyPassword(password,u.password)) return res.status(401).json({error:"Invalid mobile or password"});
    if(!u.password.startsWith("scrypt$")) db.prepare("UPDATE users SET password=? WHERE id=?").run(hashPassword(password),u.id);
    res.json({token:token(u),user:publicUser(u.id),message:"Login successful"});
  }catch(e){res.status(500).json({error:"Login failed"});}
});

app.get("/api/me",auth,(req,res)=>res.json({user:publicUser(req.user.id)}));

app.put("/api/profile",auth,(req,res)=>{
  const b=req.body||{};
  db.prepare(`UPDATE users SET name=COALESCE(?,name),email=COALESCE(?,email),address=COALESCE(?,address),lat=COALESCE(?,lat),lng=COALESCE(?,lng),
    skills=COALESCE(?,skills),experience=COALESCE(?,experience),profile_photo=COALESCE(?,profile_photo),licence_photo=COALESCE(?,licence_photo),
    aadhaar_number=COALESCE(?,aadhaar_number),aadhaar_front=COALESCE(?,aadhaar_front),aadhaar_back=COALESCE(?,aadhaar_back) WHERE id=?`)
    .run(b.name,b.email,b.address,b.lat,b.lng,b.skills,b.experience,b.profile_photo,b.licence_photo,b.aadhaar_number,b.aadhaar_front,b.aadhaar_back,req.user.id);
  res.json({user:publicUser(req.user.id),message:"Profile updated"});
});

app.post("/api/jobs",auth,role("customer"),(req,res)=>{
  const b=req.body||{};
  if(!String(b.category||"").trim()||!String(b.service||"").trim()||!String(b.description||"").trim()) return res.status(400).json({error:"Category, service and description required"});
  const r=db.prepare(`INSERT INTO jobs(customer_id,category,service,description,quantity,photo,lat,lng,address,preferred_date,preferred_time,emergency) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(req.user.id,String(b.category).trim(),String(b.service).trim(),String(b.description).trim(),String(b.quantity||""),String(b.photo||""),b.lat??null,b.lng??null,String(b.address||""),String(b.preferred_date||""),String(b.preferred_time||""),b.emergency?1:0);
  const job=fullJob(r.lastInsertRowid); notifyNearbyProviders(job); notify(1,"job","New customer requirement",`Customer ${job.customer_name||""} posted ${job.service} requirement #${job.id}.`,job.id); res.json({job,message:"Requirement posted"});
});

app.post("/api/jobs/:id/view",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id)); if(!j) return res.status(404).json({error:"Job not found"});
  if(req.user.id!==j.customer_id) db.prepare("INSERT OR IGNORE INTO job_views(job_id,viewer_id) VALUES(?,?)").run(j.id,req.user.id);
  const visitors=db.prepare(`SELECT u.id,u.name,u.mobile,u.role,jv.created_at FROM job_views jv JOIN users u ON u.id=jv.viewer_id WHERE jv.job_id=? AND u.role='customer' ORDER BY jv.created_at DESC`).all(j.id);
  res.json({count:visitors.length,visitors});
});
app.get("/api/jobs/:id/visitors",auth,(req,res)=>{
  const j=db.prepare("SELECT customer_id FROM jobs WHERE id=?").get(Number(req.params.id)); if(!j) return res.status(404).json({error:"Job not found"});
  if(req.user.role!=="admin"&&req.user.id!==j.customer_id) return res.status(403).json({error:"Admin/customer access only"});
  res.json({visitors:db.prepare(`SELECT u.id,u.name,u.mobile,u.role,jv.created_at FROM job_views jv JOIN users u ON u.id=jv.viewer_id WHERE jv.job_id=? AND u.role='customer' ORDER BY jv.created_at DESC`).all(req.params.id)});
});
app.post("/api/jobs/:id/completion-photos",auth,role(...PROVIDER_ROLES),(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j||j.assigned_id!==req.user.id) return res.status(403).json({error:"Only assigned professional can upload completion photos"});
  const photos=Array.isArray(req.body.photos)?req.body.photos:[req.body.photo]; const valid=photos.filter(x=>typeof x==="string"&&x.startsWith("data:image/"));
  if(!valid.length) return res.status(400).json({error:"Upload at least one image"});
  const caption=String(req.body.caption||`${j.service} completed by Smart Electro professional`);
  for(const photo of valid.slice(0,8)) db.prepare("INSERT INTO work_posts(job_id,provider_id,caption,photo,approval_status) VALUES(?,?,?,?,?)").run(j.id,req.user.id,caption,photo,"pending");
  const mode=db.prepare("SELECT value FROM settings WHERE key='approval_mode'").get()?.value||"manual";
  if(mode==="auto"){ db.prepare("UPDATE work_posts SET approval_status='approved' WHERE job_id=?").run(j.id); db.prepare("UPDATE jobs SET completion_approval='approved',status='Payment Pending',completion_rejection_reason='' WHERE id=?").run(j.id); notify(j.customer_id,"work","Work approved automatically",`Completion photos for job #${j.id} passed auto-approval. Payment is now pending.`,j.id); }
  else { db.prepare("UPDATE jobs SET completion_approval='pending',status='Admin Review Pending' WHERE id=?").run(j.id); notify(1,"approval","Work approval required",`Job #${j.id} completion photos are waiting for Admin approval.`,j.id); notify(j.customer_id,"work","Work sent for admin approval",`Completion photos for job #${j.id} were uploaded and are awaiting Admin approval.`,j.id); }
  res.json({message:mode==="auto"?"Completion photos uploaded and auto-approved":"Completion photos uploaded. Waiting for Admin approval.",approval_mode:mode});
});
app.get("/api/jobs/:id/work-posts",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id)); if(!j) return res.status(404).json({error:"Job not found"});
  if(req.user.role!=="admin"&&req.user.id!==j.customer_id&&req.user.id!==j.assigned_id) return res.status(403).json({error:"Not allowed"});
  res.json({posts:db.prepare("SELECT id FROM work_posts WHERE job_id=? ORDER BY id DESC").all(j.id).map(x=>publicPost(x.id,req.user.id))});
});
app.get("/api/public/work-posts",(req,res)=>res.json({posts:db.prepare("SELECT id FROM work_posts WHERE approval_status='approved' ORDER BY id DESC LIMIT 100").all().map(x=>publicPost(x.id,null))}));
app.get("/api/public/work-posts/:id/comments",auth,(req,res)=>res.json({comments:db.prepare(`SELECT c.*,u.name,u.role FROM post_comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id DESC`).all(req.params.id)}));
app.post("/api/public/work-posts/:id/like",auth,(req,res)=>{const id=Number(req.params.id);const ex=db.prepare("SELECT id FROM post_likes WHERE post_id=? AND user_id=?").get(id,req.user.id);if(ex)db.prepare("DELETE FROM post_likes WHERE id=?").run(ex.id);else db.prepare("INSERT INTO post_likes(post_id,user_id) VALUES(?,?)").run(id,req.user.id);res.json({post:publicPost(id,req.user.id)});});
app.post("/api/public/work-posts/:id/save",auth,(req,res)=>{const id=Number(req.params.id);const ex=db.prepare("SELECT id FROM post_saves WHERE post_id=? AND user_id=?").get(id,req.user.id);if(ex)db.prepare("DELETE FROM post_saves WHERE id=?").run(ex.id);else db.prepare("INSERT INTO post_saves(post_id,user_id) VALUES(?,?)").run(id,req.user.id);res.json({post:publicPost(id,req.user.id)});});
app.post("/api/public/work-posts/:id/comment",auth,(req,res)=>{const comment=String(req.body.comment||"").trim();if(!comment)return res.status(400).json({error:"Comment required"});db.prepare("INSERT INTO post_comments(post_id,user_id,comment) VALUES(?,?,?)").run(req.params.id,req.user.id,comment);res.json({message:"Comment added",post:publicPost(Number(req.params.id),req.user.id)});});
app.get("/api/notifications",auth,(req,res)=>res.json({notifications:db.prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.id),unread:db.prepare("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND read=0").get(req.user.id).c}));
app.put("/api/notifications/read",auth,(req,res)=>{db.prepare("UPDATE notifications SET read=1 WHERE user_id=?").run(req.user.id);res.json({success:true});});
app.get("/api/settings/public",(req,res)=>{const s=companySettings();res.json({...s,adsense_client:db.prepare("SELECT value FROM settings WHERE key='adsense_client'").get()?.value||"",adsense_slot:db.prepare("SELECT value FROM settings WHERE key='adsense_slot'").get()?.value||""});});

app.get("/api/jobs/mine",auth,(req,res)=>{
  try{
    let ids=[];
    if(req.user.role==="customer") ids=db.prepare("SELECT id FROM jobs WHERE customer_id=? ORDER BY id DESC").all(req.user.id);
    else if(req.user.role==="admin") ids=db.prepare("SELECT id FROM jobs ORDER BY id DESC").all();
    else ids=db.prepare(`SELECT DISTINCT j.id FROM jobs j LEFT JOIN job_offers o ON o.job_id=j.id WHERE j.assigned_id=? OR o.provider_id=? ORDER BY j.id DESC`).all(req.user.id,req.user.id);
    res.json({jobs:ids.map(x=>fullJob(x.id))});
  }catch(e){res.status(500).json({error:"Could not load bookings"});}
});

app.get("/api/jobs/nearby",auth,role(...PROVIDER_ROLES),(req,res)=>{
  const jobs=db.prepare(`SELECT id FROM jobs WHERE status='Request Received' ORDER BY emergency DESC,id DESC`).all().map(x=>publicJob(fullJob(x.id),req.user));
  res.json({jobs});
});

app.get("/api/jobs/:id",auth,(req,res)=>{
  const j=fullJob(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Job not found"});
  if(!providerCanSeeJob(j,req.user)) return res.status(403).json({error:"Not your job"});
  res.json({job:publicJob(j,req.user)});
});

app.post("/api/jobs/:id/accept",auth,role(...PROVIDER_ROLES),(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Job not found"});
  const p=publicUser(req.user.id);
  if(!p.verified) return res.status(403).json({error:"Your profile is not verified by admin"});
  if(!p.available) return res.status(403).json({error:"Set your status Online first"});
  const tx=db.transaction(()=>{
    const fresh=db.prepare("SELECT * FROM jobs WHERE id=?").get(j.id);
    if(fresh.status!=="Request Received") return false;
    db.prepare("INSERT OR IGNORE INTO job_offers(job_id,provider_id,status) VALUES(?,?,?)").run(fresh.id,req.user.id,"accepted");
    db.prepare("UPDATE jobs SET assigned_id=?,status='Accepted' WHERE id=? AND status='Request Received'").run(req.user.id,fresh.id);
    return true;
  });
  if(!tx()) return res.status(409).json({error:"Job was already accepted by another professional"});
  const accepted=fullJob(j.id); notify(accepted.customer_id,"job","Job accepted",`${accepted.electrician_name||"Professional"} accepted your ${accepted.service} requirement #${j.id}.`,j.id); res.json({message:"Job accepted successfully",job:accepted});
});

app.post("/api/jobs/:id/reject",auth,role(...PROVIDER_ROLES),(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Job not found"});
  db.prepare("INSERT OR REPLACE INTO job_offers(job_id,provider_id,status) VALUES(?,?,?)").run(j.id,req.user.id,"rejected");
  res.json({message:"Job rejected"});
});

app.put("/api/jobs/:id/status",auth,(req,res)=>{
  const status=String(req.body.status||"");
  if(!JOB_STATUSES.includes(status)) return res.status(400).json({error:"Invalid status"});
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Not found"});
  if(req.user.role!=="admin" && req.user.id!==j.assigned_id) return res.status(403).json({error:"Only the assigned professional or admin can update work status"});
  if(req.user.role!=="admin" && status!==NEXT_STATUS[j.status]) return res.status(409).json({error:`Next allowed status is ${NEXT_STATUS[j.status]||"none"}`});
  if(status==="Work Completed" && !["Work Started","Admin Review Pending"].includes(j.status)) return res.status(409).json({error:"Work must be started before completion"});
  db.prepare("UPDATE jobs SET status=? WHERE id=?").run(status,j.id);
  if(status==="Work Completed") { notify(j.customer_id,"work","Work completed",`Work for job #${j.id} is marked completed. Completion photos are now awaiting photo/Admin approval.`,j.id); }
  if(status==="On the Way") notify(j.customer_id,"status","Professional is on the way",`${j.electrician_name||"Professional"} is on the way for job #${j.id}.`,j.id);
  res.json({message:"Status updated",job:fullJob(j.id)});
});

app.get("/api/jobs/:id/quotations",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Not found"});
  if(!providerCanSeeJob(j,req.user)) return res.status(403).json({error:"Not allowed"});
  const q=db.prepare(`SELECT q.*,u.name contractor_name,u.mobile contractor_mobile,u.profile_photo contractor_photo,u.role contractor_role,u.rating,u.verified FROM quotations q JOIN users u ON u.id=q.contractor_id WHERE q.job_id=? ORDER BY q.amount`).all(j.id);
  res.json({quotations:q});
});

app.post("/api/quotations",auth,role(...PROVIDER_ROLES),(req,res)=>{
  const b=req.body||{}, j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(b.job_id));
  if(!j) return res.status(404).json({error:"Job not found"});
  if(j.assigned_id!==req.user.id) return res.status(403).json({error:"Only the assigned professional can submit a quotation"});
  const p=publicUser(req.user.id); if(!p.verified) return res.status(403).json({error:"Admin verification required"});
  if(!["Accepted","On the Way","Arrived","Work Started"].includes(j.status)) return res.status(409).json({error:"Quotation can be submitted only after the job is accepted"});
  const amount=Number(b.amount||0); if(!Number.isFinite(amount)||amount<=0) return res.status(400).json({error:"Valid quotation amount required"});
  const r=db.prepare(`INSERT INTO quotations(job_id,contractor_id,amount,material_cost,labour_cost,gst,completion_days,terms,pdf,status) VALUES(?,?,?,?,?,?,?,?,?,?)`)
    .run(j.id,req.user.id,amount,Number(b.material_cost||0),Number(b.labour_cost||0),Number(b.gst||0),Number(b.completion_days||0),String(b.terms||""),String(b.pdf||""),"submitted");
  const quotation=db.prepare("SELECT * FROM quotations WHERE id=?").get(r.lastInsertRowid); notify(j.customer_id,"quotation","New quotation received",`${p.name||"Professional"} submitted a quotation of ₹${amount} for job #${j.id}.`,j.id); res.json({quotation,message:"Quotation submitted"});
});

app.post("/api/quotations/:id/accept",auth,role("customer"),(req,res)=>{
  const q=db.prepare("SELECT * FROM quotations WHERE id=?").get(Number(req.params.id));
  if(!q) return res.status(404).json({error:"Not found"});
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(q.job_id);
  if(!j||j.customer_id!==req.user.id) return res.status(403).json({error:"Not your job"});
  if(q.status!=="submitted") return res.status(409).json({error:"Quotation is no longer available"});
  const tx=db.transaction(()=>{
    db.prepare("UPDATE quotations SET status='accepted' WHERE id=? AND status='submitted'").run(q.id);
    db.prepare("UPDATE quotations SET status='rejected' WHERE job_id=? AND id<>? AND status='submitted'").run(j.id,q.id);
    db.prepare("UPDATE jobs SET assigned_id=?,final_amount=?,status='Accepted' WHERE id=?").run(q.contractor_id,q.amount,j.id);
  });
  tx();
  res.json({message:"Quotation accepted",job:fullJob(j.id)});
});

app.post("/api/payments",auth,role("customer"),(req,res)=>{
  const b=req.body||{}, j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(b.job_id));
  if(!j||j.customer_id!==req.user.id) return res.status(403).json({error:"Invalid job"});
  if(j.completion_approval!=="approved" || !["Payment Pending"].includes(j.status)) return res.status(409).json({error:"Payment is available only after Admin approval"});
  const amount=Number(b.amount||j.final_amount||0); if(!Number.isFinite(amount)||amount<=0) return res.status(400).json({error:"Payment amount required"});
  if(!Number(j.final_amount)||j.final_amount<=0) return res.status(409).json({error:"Admin must set the approved payment amount before payment"});
  if(Math.abs(amount-Number(j.final_amount))>0.009) return res.status(400).json({error:"Payment amount must match the approved final amount"});
  const r=db.prepare(`INSERT INTO payments(job_id,customer_id,amount,method,status,transaction_id) VALUES(?,?,?,?,?,?)`).run(j.id,req.user.id,amount,String(b.method||"Cash"),"paid",String(b.transaction_id||"DEMO-"+Date.now()));
  db.prepare("UPDATE jobs SET status='Payment Completed' WHERE id=?").run(j.id);
  res.json({payment:db.prepare("SELECT * FROM payments WHERE id=?").get(r.lastInsertRowid),message:"Payment recorded"});
});

app.get("/api/jobs/:id/payments",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Not found"});
  if(req.user.role!=="admin"&&j.customer_id!==req.user.id&&j.assigned_id!==req.user.id) return res.status(403).json({error:"Not allowed"});
  res.json({payments:db.prepare("SELECT * FROM payments WHERE job_id=? ORDER BY id DESC").all(j.id)});
});

app.post("/api/jobs/:id/close",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j) return res.status(404).json({error:"Not found"});
  if(req.user.role!=="admin" && req.user.id!==j.customer_id) return res.status(403).json({error:"Only customer or admin can close"});
  if(j.status!=="Payment Completed") return res.status(409).json({error:"Job can be closed only after payment is completed"});
  const openComplaint=db.prepare("SELECT id FROM complaints WHERE job_id=? AND status='open'").get(j.id); if(openComplaint) return res.status(409).json({error:"Job cannot be closed while a complaint/dispute is open"});
  db.prepare("UPDATE jobs SET status='Closed' WHERE id=?").run(j.id);
  notify(j.assigned_id,"job","Job closed",`Job #${j.id} has been closed after payment completion.`,j.id);
  notify(j.customer_id,"job","Job closed","Your job has been closed successfully.",j.id);
  res.json({message:"Job closed",job:fullJob(j.id)});
});

app.post("/api/reviews",auth,role("customer"),(req,res)=>{
  const b=req.body||{}, j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(b.job_id));
  if(!j) return res.status(404).json({error:"Not found"});
  if(j.customer_id!==req.user.id||!j.assigned_id) return res.status(403).json({error:"Only the customer of an assigned job can review"});
  if(!["Payment Completed","Closed"].includes(j.status)) return res.status(409).json({error:"Review is available after payment"});
  if(db.prepare("SELECT id FROM reviews WHERE job_id=? AND from_user=?").get(j.id,req.user.id)) return res.status(409).json({error:"You have already reviewed this job"});
  const rating=Math.max(1,Math.min(5,Math.round(Number(b.rating||0))));
  db.prepare("INSERT INTO reviews(job_id,from_user,to_user,rating,review) VALUES(?,?,?,?,?)").run(j.id,req.user.id,j.assigned_id,rating,String(b.review||""));
  const avg=db.prepare("SELECT AVG(rating) a FROM reviews WHERE to_user=?").get(j.assigned_id).a||0;
  db.prepare("UPDATE users SET rating=? WHERE id=?").run(Number(avg.toFixed(2)),j.assigned_id);
  notify(j.assigned_id,"review","New rating received",`Customer rated your work ${rating}/5 for job #${j.id}.`,j.id); res.json({message:"Review submitted",rating:Number(avg.toFixed(2))});
});

app.post("/api/complaints",auth,(req,res)=>{
  const message=String(req.body.message||"").trim(); if(!message) return res.status(400).json({error:"Complaint message required"});
  const r=db.prepare("INSERT INTO complaints(job_id,user_id,message) VALUES(?,?,?)").run(req.body.job_id||null,req.user.id,message);
  res.json({id:r.lastInsertRowid,message:"Complaint submitted"});
});

app.get("/api/providers",auth,(req,res)=>{
  const rows=db.prepare(`SELECT id,name,mobile,role,skills,experience,profile_photo,licence_photo,verified,available,rating,jobs_completed,lat,lng FROM users WHERE role<>'customer' AND role<>'admin' AND verified=1 ORDER BY available DESC,rating DESC,id DESC`).all();
  res.json({providers:rows});
});
app.put("/api/location",auth,role(...PROVIDER_ROLES),(req,res)=>{ const lat=Number(req.body.lat),lng=Number(req.body.lng); if(!Number.isFinite(lat)||!Number.isFinite(lng)) return res.status(400).json({error:"Valid GPS coordinates required"}); db.prepare("UPDATE users SET lat=?,lng=? WHERE id=?").run(lat,lng,req.user.id); res.json({success:true,lat,lng}); });
app.put("/api/availability",auth,role(...PROVIDER_ROLES),(req,res)=>{
  db.prepare("UPDATE users SET available=? WHERE id=?").run(req.body.available?1:0,req.user.id);
  res.json({message:req.body.available?"Online":"Offline",user:publicUser(req.user.id)});
});

app.get("/api/admin/job-visitors",auth,role("admin"),(req,res)=>{
  const rows=db.prepare(`SELECT j.id job_id,j.service,j.status,c.name customer_name,COUNT(DISTINCT v.viewer_id) visitor_count
    FROM jobs j JOIN users c ON c.id=j.customer_id LEFT JOIN job_views v ON v.job_id=j.id GROUP BY j.id ORDER BY j.id DESC`).all();
  res.json({jobs:rows});
});
app.get("/api/admin/job/:id/visitors",auth,role("admin"),(req,res)=>res.json({visitors:db.prepare(`SELECT u.name,u.mobile,u.role,jv.created_at FROM job_views jv JOIN users u ON u.id=jv.viewer_id WHERE jv.job_id=? ORDER BY jv.created_at DESC`).all(req.params.id)}));
app.get("/api/admin/work-posts",auth,role("admin"),(req,res)=>res.json({posts:db.prepare(`SELECT wp.*,u.name provider_name,u.mobile provider_mobile,j.service,j.customer_id FROM work_posts wp JOIN users u ON u.id=wp.provider_id JOIN jobs j ON j.id=wp.job_id ORDER BY wp.id DESC`).all()}));
app.put("/api/admin/work-posts/:id/approve",auth,role("admin"),(req,res)=>{
  const post=db.prepare("SELECT * FROM work_posts WHERE id=?").get(Number(req.params.id)); if(!post)return res.status(404).json({error:"Post not found"});
  const approved=req.body.approved?1:0; const status=approved?"approved":"rejected"; db.prepare("UPDATE work_posts SET approval_status=? WHERE id=?").run(status,post.id);
  const pending=db.prepare("SELECT COUNT(*) c FROM work_posts WHERE job_id=? AND approval_status='pending'").get(post.job_id).c;
  if(approved){ const rejected=db.prepare("SELECT COUNT(*) c FROM work_posts WHERE job_id=? AND approval_status='rejected'").get(post.job_id).c; if(!rejected && pending===0){db.prepare("UPDATE jobs SET completion_approval='approved',status='Payment Pending',completion_rejection_reason='' WHERE id=?").run(post.job_id); const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(post.job_id); db.prepare("UPDATE users SET jobs_completed=jobs_completed+1 WHERE id=?").run(j.assigned_id); notify(j.customer_id,"approval","Work approved","Admin approved the completion photos. Payment is now pending.",j.id); notify(j.assigned_id,"approval","Work approved","Admin approved your completion photos. Payment is now pending.",j.id);}}
  else { const reason=String(req.body.reason||"Work completion rejected by Admin"); db.prepare("UPDATE jobs SET completion_approval='rejected',status='Work Completed',completion_rejection_reason=? WHERE id=?").run(reason,post.job_id); const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(post.job_id); notify(j.assigned_id,"approval","Work approval rejected",reason,j.id); notify(j.customer_id,"approval","Work approval rejected",reason,j.id); }
  res.json({success:true,message:approved?"Photo approved":"Photo rejected"});
});
app.get("/api/admin/settings",auth,role("admin"),(req,res)=>res.json({approval_mode:db.prepare("SELECT value FROM settings WHERE key='approval_mode'").get()?.value||"manual"}));
app.put("/api/admin/settings/approval-mode",auth,role("admin"),(req,res)=>{
  const mode=req.body.mode==="auto"?"auto":"manual";
  db.prepare("INSERT INTO settings(key,value) VALUES('approval_mode',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(mode);
  if(mode==="auto"){
    const jobs=db.prepare("SELECT DISTINCT job_id FROM work_posts WHERE approval_status='pending'").all();
    for(const row of jobs){
      db.prepare("UPDATE work_posts SET approval_status='approved' WHERE job_id=? AND approval_status='pending'").run(row.job_id);
      const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(row.job_id);
      if(j && j.status==="Admin Review Pending"){
        db.prepare("UPDATE jobs SET completion_approval='approved',status='Payment Pending',completion_rejection_reason='' WHERE id=?").run(j.id);
        if(j.assigned_id) db.prepare("UPDATE users SET jobs_completed=jobs_completed+1 WHERE id=?").run(j.assigned_id);
        notify(j.customer_id,"approval","Work auto-approved","Admin Auto Approval approved the completion photos. Payment is now pending.",j.id);
        notify(j.assigned_id,"approval","Work auto-approved","Your completion photos were auto-approved. Payment is now pending.",j.id);
      }
    }
  }
  res.json({success:true,approval_mode:mode,message:`Work approval mode set to ${mode}${mode==="auto"?". Pending eligible completion photos were auto-approved.":"."}`});
});
app.get("/api/admin/revenue-settings",auth,role("admin"),(req,res)=>res.json({commission_rate:Number(db.prepare("SELECT value FROM settings WHERE key='commission_rate'").get()?.value||2),adsense_client:db.prepare("SELECT value FROM settings WHERE key='adsense_client'").get()?.value||"",adsense_slot:db.prepare("SELECT value FROM settings WHERE key='adsense_slot'").get()?.value||""}));
app.put("/api/admin/revenue-settings",auth,role("admin"),(req,res)=>{const rate=Number(req.body.commission_rate);if(!Number.isFinite(rate)||rate<0||rate>3)return res.status(400).json({error:"Commission rate must be between 0% and 3%"});const client=String(req.body.adsense_client||"").trim();const slot=String(req.body.adsense_slot||"").trim();if(client && !client.startsWith("ca-pub-"))return res.status(400).json({error:"AdSense client must start with ca-pub-"});db.prepare("INSERT INTO settings(key,value) VALUES('commission_rate',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(rate));db.prepare("INSERT INTO settings(key,value) VALUES('adsense_client',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(client);db.prepare("INSERT INTO settings(key,value) VALUES('adsense_slot',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(slot);res.json({success:true,message:"Revenue settings updated"});});
app.put("/api/admin/branding",auth,role("admin"),(req,res)=>{let logo=String(req.body.logo||"");if(logo && !logo.startsWith("data:image/")) return res.status(400).json({error:"Logo must be an image"});if(!logo) logo=companySettings().logo;db.prepare("INSERT INTO settings(key,value) VALUES('company_logo',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(logo);db.prepare("INSERT INTO settings(key,value) VALUES('company_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(req.body.company_name||"Shubhraj Energy Systems"));res.json({success:true,settings:companySettings()});});
app.get("/api/admin/stats",auth,role("admin"),(req,res)=>{
  const count=t=>db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c;
  const rate=Number(db.prepare("SELECT value FROM settings WHERE key='commission_rate'").get()?.value||2);
  const paid=Number(db.prepare("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='paid'").get().s||0);
  const commission=paid*rate/100;
  res.json({customers:db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,providers:db.prepare("SELECT COUNT(*) c FROM users WHERE role<>'customer' AND role<>'admin'").get().c,pending_verification:db.prepare("SELECT COUNT(*) c FROM users WHERE role<>'admin' AND verified=0").get().c,verified_providers:db.prepare("SELECT COUNT(*) c FROM users WHERE role<>'customer' AND role<>'admin' AND verified=1").get().c,jobs:count("jobs"),completed:db.prepare("SELECT COUNT(*) c FROM jobs WHERE status IN ('Work Completed','Admin Review Pending','Payment Pending','Payment Completed','Closed')").get().c,work_completed:db.prepare("SELECT COUNT(*) c FROM jobs WHERE status IN ('Work Completed','Admin Review Pending','Payment Pending','Payment Completed','Closed')").get().c,payment_completed:db.prepare("SELECT COUNT(*) c FROM jobs WHERE status='Payment Completed'").get().c,closed:db.prepare("SELECT COUNT(*) c FROM jobs WHERE status='Closed'").get().c,quotations:count("quotations"),payments:count("payments"),complaints:db.prepare("SELECT COUNT(*) c FROM complaints WHERE status='open'").get().c,paid_volume:paid,commission_rate:rate,commission_earned:commission});
});
app.get("/api/admin/users",auth,role("admin"),(req,res)=>res.json({users:db.prepare(`SELECT id,name,mobile,email,address,role,skills,experience,profile_photo,licence_photo,aadhaar_number,aadhaar_front,aadhaar_back,aadhaar_otp_verified,verified,available,rating,jobs_completed,created_at FROM users ORDER BY id DESC`).all()}));
app.put("/api/admin/users/:id/verify",auth,role("admin"),(req,res)=>{
  const id=Number(req.params.id), verified=req.body.verified?1:0, u=db.prepare("SELECT id,role FROM users WHERE id=?").get(id);
  if(!u) return res.status(404).json({error:"User not found"}); if(u.role==="admin") return res.status(400).json({error:"Admin cannot be verified here"});
  db.prepare("UPDATE users SET verified=?,available=? WHERE id=?").run(verified,verified,id);
  res.json({success:true,message:verified?"Verification successful":"Verification removed",user:publicUser(id)});
});
app.put("/api/admin/users/:id/suspend",auth,role("admin"),(req,res)=>{const id=Number(req.params.id);db.prepare("UPDATE users SET available=0,verified=0 WHERE id=?").run(id);res.json({success:true,message:"User suspended",user:publicUser(id)});});

app.put("/api/admin/jobs/:id/amount",auth,role("admin"),(req,res)=>{
  const id=Number(req.params.id), amount=Number(req.body.amount);
  if(!Number.isFinite(amount)||amount<=0) return res.status(400).json({error:"Enter a valid payment amount"});
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(id); if(!j)return res.status(404).json({error:"Job not found"});
  if(!["Payment Pending","Payment Completed"].includes(j.status)) return res.status(409).json({error:"Amount can be set after Admin approval"});
  db.prepare("UPDATE jobs SET final_amount=? WHERE id=?").run(amount,id);
  notify(j.customer_id,"payment","Payment amount updated",`Admin set the payment amount for job #${id} to ₹${amount}.`,id);
  res.json({success:true,amount,message:"Payment amount updated"});
});
app.get("/api/jobs/:id/messages",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id));
  if(!j || (req.user.role!=="admin" && req.user.id!==j.customer_id && req.user.id!==j.assigned_id)) return res.status(403).json({error:"Not allowed"});
  res.json({messages:db.prepare(`SELECT m.*,u.name sender_name,u.role sender_role FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.job_id=? ORDER BY m.id ASC`).all(j.id)});
});
app.post("/api/jobs/:id/messages",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id)); const text=String(req.body.message||"").trim();
  if(!j || !text) return res.status(400).json({error:"Job and message are required"});
  if(req.user.role!=="admin" && req.user.id!==j.customer_id && req.user.id!==j.assigned_id) return res.status(403).json({error:"Not allowed"});
  const receiver=j.customer_id===req.user.id?j.assigned_id:j.customer_id; if(!receiver) return res.status(409).json({error:"No other participant assigned yet"});
  const r=db.prepare("INSERT INTO messages(job_id,sender_id,receiver_id,message) VALUES(?,?,?,?)").run(j.id,req.user.id,receiver,text); notify(receiver,"message","New job message",`You have a new message on job #${j.id}.`,j.id);
  res.json({message:db.prepare("SELECT m.*,u.name sender_name,u.role sender_role FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?").get(r.lastInsertRowid)});
});
app.get("/api/jobs/:id/invoice",auth,(req,res)=>{
  const j=db.prepare("SELECT * FROM jobs WHERE id=?").get(Number(req.params.id)); if(!j || (req.user.role!=="admin"&&req.user.id!==j.customer_id&&req.user.id!==j.assigned_id)) return res.status(403).json({error:"Not allowed"});
  if(!["Payment Completed","Closed"].includes(j.status)) return res.status(409).json({error:"Invoice is available after payment"});
  let inv=db.prepare("SELECT * FROM invoices WHERE job_id=?").get(j.id);
  if(!inv){const no=`SE-${new Date().getFullYear()}-${String(j.id).padStart(6,"0")}`;const r=db.prepare("INSERT INTO invoices(job_id,invoice_no,amount) VALUES(?,?,?)").run(j.id,no,j.final_amount||0);inv=db.prepare("SELECT * FROM invoices WHERE id=?").get(r.lastInsertRowid);}
  res.json({invoice:inv,job:publicJob(fullJob(j.id),req.user)});
});

app.get("/api/admin/payments",auth,role("admin"),(req,res)=>res.json({payments:db.prepare(`SELECT p.*,j.service,c.name customer_name,u.name provider_name FROM payments p JOIN jobs j ON j.id=p.job_id JOIN users c ON c.id=p.customer_id LEFT JOIN users u ON u.id=j.assigned_id ORDER BY p.id DESC`).all()}));
app.get("/api/admin/complaints",auth,role("admin"),(req,res)=>res.json({complaints:db.prepare(`SELECT c.*,u.name user_name,u.mobile,j.service FROM complaints c JOIN users u ON u.id=c.user_id LEFT JOIN jobs j ON j.id=c.job_id ORDER BY c.id DESC`).all()}));
app.put("/api/admin/complaints/:id",auth,role("admin"),(req,res)=>{if(!["open","resolved","closed"].includes(req.body.status))return res.status(400).json({error:"Invalid status"});db.prepare("UPDATE complaints SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({success:true,message:"Complaint updated"});});

app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:"Internal server error"});});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"../public/index.html")));
app.listen(PORT,"0.0.0.0",()=>console.log(`Smart Electro running on port ${PORT}`));
