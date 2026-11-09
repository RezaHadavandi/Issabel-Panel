'use strict';
const net=require('net'),crypto=require('crypto'),dns=require('dns').promises,express=require('express'),Database=require('better-sqlite3');
const E=process.env,TECH=E.PEER_TECH||'SIP',SESS=8*36e5,VERSION=require('./package.json').version,https=require('https'),http=require('http'),fs=require('fs');
if(!E.APP_SECRET||E.APP_SECRET.length<32||!E.HOOK_SECRET||E.HOOK_SECRET.length<24){console.error('APP_SECRET / HOOK_SECRET تنظیم نشده یا کوتاه است');process.exit(1)}
// ---------- crypto ----------
const KEY=crypto.createHash('sha256').update(E.APP_SECRET).digest(),sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const eq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const hashPw=p=>{const s=crypto.randomBytes(16);return s.toString('hex')+':'+crypto.scryptSync(p,s,64).toString('hex')};
const checkPw=(p,h)=>{const[s,x]=String(h).split(':');return !!x&&eq(crypto.scryptSync(p,Buffer.from(s,'hex'),64).toString('hex'),x)};
const enc=t=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',KEY,iv),d=Buffer.concat([c.update(t,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),d]).toString('base64')};
const dec=t=>{const b=Buffer.from(t,'base64'),d=crypto.createDecipheriv('aes-256-gcm',KEY,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8')};
const DUMMY=hashPw('x');
// ---------- db ----------
const db=new Database(E.DB_PATH||'./panel.db');db.pragma('journal_mode=WAL');db.pragma('synchronous=NORMAL');db.pragma('foreign_keys=ON');
db.exec(`CREATE TABLE IF NOT EXISTS units(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,supervisor_id INTEGER);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL COLLATE NOCASE,name TEXT,pass TEXT NOT NULL,role TEXT NOT NULL,ext TEXT UNIQUE,unit_id INTEGER,active INTEGER DEFAULT 1,fails INTEGER DEFAULT 0,locked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY,uid INTEGER,exp INTEGER);
CREATE TABLE IF NOT EXISTS calls(id INTEGER PRIMARY KEY,uid TEXT UNIQUE,ts INTEGER,caller TEXT,agent TEXT,dur INTEGER,score INTEGER,sms TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS audit(ts INTEGER,uid INTEGER,act TEXT,info TEXT);`);
try{db.exec('ALTER TABLE calls ADD COLUMN queue TEXT')}catch{}
db.exec(`CREATE TABLE IF NOT EXISTS phones(id INTEGER PRIMARY KEY,name TEXT,ip TEXT UNIQUE,https INTEGER,user TEXT,pw TEXT);CREATE INDEX IF NOT EXISTS ci ON calls(caller);CREATE INDEX IF NOT EXISTS cts ON calls(ts);`);
const getCfg=k=>{const r=db.prepare('SELECT v FROM settings WHERE k=?').get(k);return r?JSON.parse(r.v):{}};
const setCfg=(k,v)=>db.prepare('INSERT INTO settings VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k,JSON.stringify(v));
const audit=(q,a,i)=>db.prepare('INSERT INTO audit VALUES(?,?,?,?)').run(Date.now(),q.user?q.user.id:0,a,String(i||'').slice(0,200));
if(!db.prepare('SELECT 1 FROM users').get()){const p=crypto.randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO users(username,name,pass,role) VALUES(?,?,?,?)').run('admin','مدیر سیستم',hashPw(p),'admin');console.log('ADMIN LOGIN -> username: admin  password: '+p)}
setInterval(()=>{db.prepare('DELETE FROM sessions WHERE exp<?').run(Date.now());db.prepare('DELETE FROM audit WHERE ts<?').run(Date.now()-180*864e5)},36e5);
// ---------- AMI ----------
const C={host:E.AMI_HOST||'127.0.0.1',port:+E.AMI_PORT||5038,user:E.AMI_USER,pass:E.AMI_PASS};
const callerOf=new Map();let sock,buf='',up=false,seq=0,first=true,delay=3000;const pending=new Map();
const S={channels:[],queues:[],peers:[],updated:0,error:null,seen:Date.now()};
const parse=raw=>{const o={};raw.split('\r\n').forEach(l=>{const i=l.indexOf(': ');if(i>0)o[l.slice(0,i)]=l.slice(i+2)});return o};
function onMsg(m){const p=pending.get(m.ActionID);if(!p){if(m.Event==='AgentComplete')onAgentComplete(m);else if(m.Event==='Join'||m.Event==='QueueCallerJoin'){const u=m.Uniqueid||m.UniqueID,n=m.CallerIDNum||m.CallerID;if(u&&n){if(callerOf.size>5000)callerOf.clear();callerOf.set(u,n)}}return}
  if(m.Response){if(m.Response==='Error'){pending.delete(m.ActionID);return p.rej(new Error(m.Message||'AMI error'))}
    p.res=m;if(!p.list&&m.EventList!=='start'){pending.delete(m.ActionID);p.ok({res:m,ev:p.ev})}}
  else if(m.Event){p.ev.push(m);if(m.EventList==='Complete'||/Complete$/.test(m.Event)){pending.delete(m.ActionID);p.ok({res:p.res,ev:p.ev})}}}
const LIST=new Set(['CoreShowChannels','QueueStatus','SIPpeers','PJSIPShowEndpoints']);
function action(o,ms=6000){return new Promise((ok,rej)=>{if(!up)return rej(new Error('AMI متصل نیست'));const id='a'+(++seq);pending.set(id,{ok,rej,ev:[],list:LIST.has(o.Action)});
  setTimeout(()=>{if(pending.delete(id))rej(new Error('AMI timeout'))},ms);
  sock.write(Object.entries({...o,ActionID:id}).map(([k,v])=>`${k}: ${String(v).replace(/[\r\n]/g,'')}`).join('\r\n')+'\r\n\r\n')})}
function connect(){buf='';first=true;sock=net.connect(C.port,C.host);sock.setEncoding('utf8');
  sock.on('connect',()=>{up=true;action({Action:'Login',Username:C.user,Secret:C.pass}).then(()=>{delay=3000;return action({Action:'CoreSettings'}).then(r=>{S.ver=r.res.AsteriskVersion}).catch(()=>{})}).catch(e=>{S.error=e.message;sock.destroy()})});
  sock.on('data',d=>{if(first){first=false;if(!/^Asterisk Call Manager/.test(d)){S.error='پورت مقصد، AMI آسترسک نیست (FreeSWITCH/ESL پشتیبانی نمی‌شود)';return sock.destroy()}}buf+=d;if(buf.length>1e6){buf='';sock.destroy();return}let i;while((i=buf.indexOf('\r\n\r\n'))>=0){const r=buf.slice(0,i);buf=buf.slice(i+4);onMsg(parse(r))}});
  sock.on('error',e=>{S.error=e.message});
  sock.on('close',()=>{up=false;pending.forEach(p=>p.rej(new Error('AMI closed')));pending.clear();setTimeout(connect,delay);delay=Math.min(delay*2,3e4)})}
const mext=l=>((l||'').match(/\/(\d+)/)||[])[1],chExt=c=>((c.Channel||'').match(/^(?:PJSIP|SIP|IAX2|Local)\/(\d+)/)||[])[1];
const sipP=async()=>(await action({Action:'SIPpeers'})).ev.filter(e=>e.Event==='PeerEntry').map(e=>({name:e.ObjectName,tech:'SIP',ip:e.IPaddress,status:e.Status,online:/^OK/.test(e.Status||''),busy:false}));
const pjP=async()=>(await action({Action:'PJSIPShowEndpoints'})).ev.filter(e=>e.Event==='EndpointList').map(e=>({name:e.ObjectName,tech:'PJSIP',ip:e.Contacts||'',status:e.DeviceState,online:e.DeviceState!=='Unavailable',busy:/in use|ring/i.test(e.DeviceState||'')}));
async function getPeers(){const r=await Promise.allSettled([sipP(),pjP()]);if(r.every(x=>x.status==='rejected'))throw r[0].reason;return r.flatMap(x=>x.value||[]).filter((p,i,a)=>p.name&&a.findIndex(y=>y.name===p.name)===i)}
const sec=d=>/:/.test(d||'')?d.split(':').reduce((a,x)=>a*60+(+x),0):+d||0;
const nch=c=>({...c,CallerIDNum:c.CallerIDNum??c.CallerIDnum,CallerIDName:c.CallerIDName??c.CallerIDname,Exten:c.Exten??c.Extension,Uniqueid:c.Uniqueid||c.UniqueID,Application:c.Application||c.ApplicationName,Duration:sec(c.Duration)});
async function poll(){if(!up||Date.now()-S.seen>3e4)return;try{S.channels=(await action({Action:'CoreShowChannels'})).ev.filter(e=>e.Event==='CoreShowChannel').map(nch);if(callerOf.size>5000)callerOf.clear();S.channels.forEach(c=>{if(c.CallerIDNum&&c.Uniqueid)callerOf.set(c.Uniqueid,c.CallerIDNum)});
  const qs={};(await action({Action:'QueueStatus'})).ev.forEach(e=>{if(e.Event==='QueueParams')qs[e.Queue]={...e,members:[],callers:[]};
    else if(e.Event==='QueueMember'&&qs[e.Queue])qs[e.Queue].members.push(e);else if(e.Event==='QueueEntry'&&qs[e.Queue])qs[e.Queue].callers.push({...e,CallerIDNum:e.CallerIDNum||e.CallerID})});
  S.queues=Object.values(qs);S.peers=await getPeers();const busy=new Set(S.channels.map(chExt));S.peers.forEach(p=>{if(busy.has(p.name))p.busy=true});
  S.updated=Date.now();S.error=null}catch(e){S.error=e.message}}
setInterval(poll,2500);
// ---------- scope / auth ----------
function scope(u){if(u.role==='operator')return new Set([u.ext]);if(u.role!=='supervisor')return null;
  const s=new Set(db.prepare('SELECT ext FROM users WHERE ext IS NOT NULL AND unit_id IN (SELECT id FROM units WHERE supervisor_id=?)').all(u.id).map(r=>r.ext));if(u.ext)s.add(u.ext);return s}
const cookie=(q,n)=>{const m=(q.headers.cookie||'').split(/;\s*/).find(c=>c.startsWith(n+'='));return m?m.slice(n.length+1):''};
const SQ=db.prepare('SELECT u.*,s.exp sexp FROM sessions s JOIN users u ON u.id=s.uid WHERE s.h=? AND s.exp>? AND u.active=1');
function auth(q,r,n){const sid=cookie(q,'sid');if(sid){const h=sha(sid),now=Date.now(),u=SQ.get(h,now);
  if(u){q.user=u;if(u.sexp<now+SESS-6e4)db.prepare('UPDATE sessions SET exp=? WHERE h=?').run(now+SESS,h);return n()}}r.status(401).json({error:'unauthorized'})}
const need=(...r)=>(q,s,n)=>r.includes(q.user.role)?n():s.status(403).json({error:'دسترسی مجاز نیست'});
const bad=(r,m)=>r.status(400).json({error:m}),okExt=e=>/^\d{2,8}$/.test(e||''),okQ=s=>/^[\w.-]{1,40}$/.test(s||''),ROLES=['admin','supervisor','operator','observer'];
// ---------- app ----------
const app=express();app.disable('x-powered-by');app.set('trust proxy',E.TRUST_PROXY==='1');
app.use((q,r,n)=>{r.set({'Content-Security-Policy':"default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(),microphone=(),geolocation=()','Cross-Origin-Opener-Policy':'same-origin',...(E.COOKIE_SECURE==='1'?{'Strict-Transport-Security':'max-age=31536000'}:{})});n()});
app.use(express.static(__dirname+'/public'));
app.use('/api',(q,r,n)=>express.json({limit:q.path.startsWith('/audio/')?'5mb':'10kb'})(q,r,n),(q,r,n)=>{r.set('Cache-Control','no-store');
  if(q.method!=='GET'){const o=q.headers.origin;try{if(o&&new URL(o).host!==q.headers.host)return r.status(403).json({error:'origin'})}catch{return r.status(403).json({error:'origin'})}if(!q.is('json'))return r.status(415).json({error:'json only'})}n()});
const tries=new Map();setInterval(()=>{const n=Date.now();for(const[k,v]of tries)if(n>v.r)tries.delete(k)},6e5);
app.post('/api/login',(q,r)=>{const t=tries.get(q.ip)||{n:0,r:Date.now()+9e5};if(Date.now()>t.r){t.n=0;t.r=Date.now()+9e5}tries.set(q.ip,t);
  if(++t.n>20)return r.status(429).json({error:'تلاش بیش از حد؛ بعداً امتحان کنید'});
  const{username,password}=q.body||{},u=typeof username==='string'?db.prepare('SELECT * FROM users WHERE username=?').get(username):null;
  if(u&&u.locked>Date.now())return r.status(423).json({error:'حساب موقتاً قفل است'});
  const ok=checkPw(String(password||''),u?u.pass:DUMMY)&&u&&u.active;
  if(!ok){if(u){const f=u.fails+1;db.prepare('UPDATE users SET fails=?,locked=? WHERE id=?').run(f>=5?0:f,f>=5?Date.now()+9e5:0,u.id)}return r.status(401).json({error:'نام کاربری یا رمز اشتباه است'})}
  db.prepare('UPDATE users SET fails=0,locked=0 WHERE id=?').run(u.id);const sid=crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(sha(sid),u.id,Date.now()+SESS);
  r.set('Set-Cookie',`sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESS/1000}${E.COOKIE_SECURE==='1'?'; Secure':''}`);
  audit({user:u},'login','');r.json({ok:true})});
app.post('/api/logout',auth,(q,r)=>{db.prepare('DELETE FROM sessions WHERE h=?').run(sha(cookie(q,'sid')));r.set('Set-Cookie','sid=; Max-Age=0; Path=/');r.json({ok:true})});
app.get('/api/me',auth,(q,r)=>{const{id,username,name,role,ext,unit_id}=q.user;r.json({id,username,name,role,ext,unit_id,version:VERSION})});
app.post('/api/password',auth,(q,r)=>{const{old,pw}=q.body||{};if(!checkPw(String(old||''),q.user.pass))return bad(r,'رمز فعلی اشتباه است');if(typeof pw!=='string'||pw.length<10)return bad(r,'رمز جدید حداقل ۱۰ کاراکتر');
  db.prepare('UPDATE users SET pass=? WHERE id=?').run(hashPw(pw),q.user.id);db.prepare('DELETE FROM sessions WHERE uid=? AND h!=?').run(q.user.id,sha(cookie(q,'sid')));r.json({ok:true})});
// ---------- live ----------
app.get('/api/state',auth,need('admin','supervisor','operator'),(q,r)=>{if(Date.now()-S.seen>3e4)poll();S.seen=Date.now();const u=q.user,sc=scope(u),op=u.role==='operator';
  r.json({connected:up,error:S.error,updated:S.updated,
    channels:op?[]:sc?S.channels.filter(c=>sc.has(chExt(c))||sc.has(c.CallerIDNum)||sc.has(c.ConnectedLineNum)):S.channels,
    peers:op?[]:sc?S.peers.filter(p=>sc.has(p.name)):S.peers,
    queues:S.queues.map(Q=>({...Q,members:sc?Q.members.filter(m=>sc.has(mext(m.Location))):Q.members,callers:op?[]:Q.callers}))})});
const ifaceOf=(q,e)=>{const Q=S.queues.find(x=>x.Queue===q),m=Q&&Q.members.find(m=>mext(m.Location)===e);return m?m.Location:`Local/${e}@from-queue/n`};
app.post('/api/queue/:act(add|remove|pause)',auth,need('admin','supervisor','operator'),(q,r)=>{const{queue,ext,paused}=q.body||{},act=q.params.act;
  if(!okQ(queue)||!okExt(ext))return bad(r,'ورودی نامعتبر');const sc=scope(q.user);if(sc&&!sc.has(ext))return r.status(403).json({error:'این داخلی در دسترس شما نیست'});
  const i=ifaceOf(queue,ext),a=act==='add'?{Action:'QueueAdd',Queue:queue,Interface:i,MemberName:ext}:act==='remove'?{Action:'QueueRemove',Queue:queue,Interface:i}:{Action:'QueuePause',Queue:queue,Interface:i,Paused:paused?'true':'false'};
  action(a).then(()=>{audit(q,'queue.'+act,queue+' '+ext);r.json({ok:true})}).catch(e=>r.status(502).json({error:e.message}))});
app.post('/api/originate',auth,need('admin','supervisor'),(q,r)=>{const{from,to}=q.body||{},sc=scope(q.user);
  if(!okExt(from)||!/^[\d*#+]{2,20}$/.test(to||''))return bad(r,'ورودی نامعتبر');if(sc&&!sc.has(from))return r.status(403).json({error:'مجاز نیست'});
  action({Action:'Originate',Channel:`${(S.peers.find(p=>p.name===from)||{}).tech||TECH}/${from}`,Context:'from-internal',Exten:to,Priority:1,CallerID:to,Timeout:30000,Async:'true'}).then(()=>{audit(q,'originate',from+'>'+to);r.json({ok:true})}).catch(e=>r.status(502).json({error:e.message}))});
app.post('/api/hangup',auth,need('admin','supervisor'),(q,r)=>{const ch=(q.body||{}).channel||'',sc=scope(q.user);
  if(!/^(?:PJSIP|SIP|IAX2|Local)\/[\w@.;-]+$/.test(ch))return bad(r,'کانال نامعتبر');if(sc&&!sc.has(chExt({Channel:ch})))return r.status(403).json({error:'مجاز نیست'});
  action({Action:'Hangup',Channel:ch}).then(()=>{audit(q,'hangup',ch);r.json({ok:true})}).catch(e=>r.status(502).json({error:e.message}))});
// ---------- users / units ----------
const canManage=(u,t)=>!!t&&(u.role==='admin'||(u.role==='supervisor'&&t.role==='operator'&&!!db.prepare('SELECT 1 FROM units WHERE id=? AND supervisor_id=?').get(t.unit_id,u.id)));
const PUB='id,username,name,role,ext,unit_id,active';
app.get('/api/users',auth,need('admin','supervisor'),(q,r)=>r.json(q.user.role==='admin'?db.prepare(`SELECT ${PUB} FROM users`).all():db.prepare(`SELECT ${PUB} FROM users WHERE role='operator' AND unit_id IN (SELECT id FROM units WHERE supervisor_id=?)`).all(q.user.id)));
app.get('/api/units',auth,need('admin','supervisor'),(q,r)=>r.json(db.prepare(`SELECT u.id,u.name,u.supervisor_id,(SELECT COUNT(*) FROM users WHERE unit_id=u.id) n FROM units u ${q.user.role==='admin'?'':'WHERE supervisor_id='+(+q.user.id)}`).all()));
app.post('/api/units',auth,need('admin','supervisor'),(q,r)=>{const b=q.body||{},name=String(b.name||'').trim();if(!name||name.length>60)return bad(r,'نام واحد نامعتبر');
  const sup=q.user.role==='admin'?(b.supervisor_id?+b.supervisor_id:null):q.user.id;
  if(sup&&!db.prepare("SELECT 1 FROM users WHERE id=? AND role='supervisor'").get(sup))return bad(r,'سرپرست نامعتبر');
  try{db.prepare('INSERT INTO units(name,supervisor_id) VALUES(?,?)').run(name,sup)}catch{return bad(r,'نام واحد تکراری است')}audit(q,'unit.create',name);r.json({ok:true})});
app.post('/api/users',auth,need('admin','supervisor'),(q,r)=>{const u=q.user,b=q.body||{},role=u.role==='admin'?b.role:'operator';
  if(!ROLES.includes(role))return bad(r,'نقش نامعتبر');if(!/^[a-z0-9_.-]{3,32}$/i.test(b.username||''))return bad(r,'نام کاربری نامعتبر');
  if(typeof b.password!=='string'||b.password.length<10)return bad(r,'رمز حداقل ۱۰ کاراکتر');const ext=b.ext?String(b.ext):null;if(ext&&!okExt(ext))return bad(r,'داخلی نامعتبر');
  const unit=b.unit_id?+b.unit_id:null;if(u.role==='supervisor'&&!db.prepare('SELECT 1 FROM units WHERE id=? AND supervisor_id=?').get(unit,u.id))return bad(r,'واحد نامعتبر');
  try{db.prepare('INSERT INTO users(username,name,pass,role,ext,unit_id) VALUES(?,?,?,?,?,?)').run(b.username,String(b.name||'').slice(0,60),hashPw(b.password),role,ext,unit)}catch{return bad(r,'نام کاربری یا داخلی تکراری است')}
  audit(q,'user.create',b.username+' '+role);r.json({ok:true})});
app.patch('/api/users/:id',auth,need('admin','supervisor'),(q,r)=>{const t=db.prepare('SELECT * FROM users WHERE id=?').get(+q.params.id),b=q.body||{};
  if(!canManage(q.user,t))return r.status(403).json({error:'مجاز نیست'});
  if(b.active!==undefined){if(t.id===q.user.id)return bad(r,'نمی‌توانید خودتان را غیرفعال کنید');db.prepare('UPDATE users SET active=? WHERE id=?').run(b.active?1:0,t.id);if(!b.active)db.prepare('DELETE FROM sessions WHERE uid=?').run(t.id)}
  if(b.password!==undefined){if(typeof b.password!=='string'||b.password.length<10)return bad(r,'رمز حداقل ۱۰ کاراکتر');db.prepare('UPDATE users SET pass=?,fails=0,locked=0 WHERE id=?').run(hashPw(b.password),t.id);db.prepare('DELETE FROM sessions WHERE uid=?').run(t.id)}
  if(b.unit_id!==undefined){const nu=b.unit_id?+b.unit_id:null;if(nu&&!db.prepare('SELECT 1 FROM units WHERE id=?').get(nu))return bad(r,'واحد نامعتبر');
    if(q.user.role==='supervisor'&&!db.prepare('SELECT 1 FROM units WHERE id=? AND supervisor_id=?').get(nu,q.user.id))return bad(r,'واحد نامعتبر');db.prepare('UPDATE users SET unit_id=? WHERE id=?').run(nu,t.id)}
  audit(q,'user.update',t.username);r.json({ok:true})});
// ---------- reports ----------
app.get('/api/report',auth,(q,r)=>{const u=q.user,sc=scope(u),d=s=>Date.parse((/^\d{4}-\d\d-\d\d$/.test(s)?s:new Date().toISOString().slice(0,10))+'T00:00:00'),f=d(q.query.from),t=d(q.query.to)+864e5;
  const ex=sc?[...sc].filter(Boolean):null,w=ex?`AND agent IN (${ex.map(()=>'?').join(',')||"''"})`:'',a=[f,t,...(ex||[])],names=Object.fromEntries(db.prepare('SELECT ext,name FROM users WHERE ext IS NOT NULL').all().map(x=>[x.ext,x.name])),nm=x=>({...x,name:names[x.ext]});
  r.json({agents:db.prepare(`SELECT agent ext,COUNT(*) calls,COUNT(score) rated,ROUND(AVG(score),2) avg,SUM(dur) talk FROM calls WHERE ts>=? AND ts<? ${w} GROUP BY agent ORDER BY avg DESC`).all(...a).map(nm),
    byQueue:db.prepare(`SELECT queue,agent ext,COUNT(*) calls,COUNT(score) rated,ROUND(AVG(score),2) avg FROM calls WHERE ts>=? AND ts<? ${w} GROUP BY queue,agent ORDER BY queue,avg DESC`).all(...a).map(nm),
    recent:db.prepare(`SELECT ts,caller,agent,queue,dur,score,sms FROM calls WHERE ts>=? AND ts<? ${w} ORDER BY ts DESC LIMIT 200`).all(...a)})});
let pool=null;if(E.CDR_DB_USER)pool=require('mysql2/promise').createPool({host:E.CDR_DB_HOST||'127.0.0.1',user:E.CDR_DB_USER,password:E.CDR_DB_PASS,database:'asteriskcdrdb',connectionLimit:3});
app.get('/api/cdr',auth,need('admin','observer'),async(q,r)=>{try{if(!pool)return bad(r,'CDR_DB_USER تنظیم نشده');const day=/^\d{4}-\d\d-\d\d$/.test(q.query.date||'')?q.query.date:new Date().toISOString().slice(0,10);
  r.json((await pool.query('SELECT calldate,src,dst,billsec,disposition FROM cdr WHERE calldate>=? AND calldate<DATE_ADD(?,INTERVAL 1 DAY) ORDER BY calldate DESC LIMIT 500',[day,day]))[0])}catch(e){r.status(502).json({error:'خطای دیتابیس CDR'})}});
// ---------- SMS ----------
const mob=n=>{const m=String(n).replace(/\D/g,'').match(/^(?:0098|98|0)?(9\d{9})$/);return m?'0'+m[1]:null};
const isPriv=ip=>/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|::1|fc|fd|fe80)/i.test(ip);
const fill=(s,v,f)=>String(s||'').replace(/\{(to|text|from)\}/g,(_,k)=>f(v[k]));
async function sendSms(to,text,c){if(!c.url)throw new Error('پنل پیامک تنظیم نشده');const v={to,text,from:c.line||''},url=new URL(fill(c.url,v,encodeURIComponent));
  if(url.protocol!=='https:'&&E.ALLOW_HTTP_SMS!=='1')throw new Error('فقط HTTPS مجاز است');
  if(E.ALLOW_PRIVATE_SMS!=='1'&&(await dns.lookup(url.hostname,{all:true})).some(i=>isPriv(i.address)))throw new Error('آدرس داخلی مجاز نیست (ALLOW_PRIVATE_SMS)');
  const form=c.type==='form',res=await fetch(url,{method:c.method||'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'Content-Type':form?'application/x-www-form-urlencoded':'application/json',...(c.hdr?JSON.parse(dec(c.hdr)):{})},
    body:c.method==='GET'?undefined:fill(c.body,v,form?encodeURIComponent:s=>JSON.stringify(String(s)).slice(1,-1))});
  if(!res.ok)throw new Error('پاسخ پنل پیامک: '+res.status)}
const pubSms=c=>({enabled:!!c.enabled,url:c.url||'',method:c.method||'POST',type:c.type||'json',body:c.body||'',text:c.text||'',lines:c.lines||[],line:c.line||'',has_hdr:!!c.hdr});
app.get('/api/settings',auth,need('admin'),(q,r)=>r.json({ami:{ver:S.ver||'',host:C.host+':'+C.port,connected:up&&!S.error,error:S.error},sms:pubSms(getCfg('sms')),crm:pubCrm(getCfg('crm'))}));
app.put('/api/settings/sms',auth,need('admin'),(q,r)=>{const b=q.body||{},o=getCfg('sms'),c={enabled:!!b.enabled,url:String(b.url||'').slice(0,500),method:b.method==='GET'?'GET':'POST',type:b.type==='form'?'form':'json',body:String(b.body||'').slice(0,2000),text:String(b.text||'').slice(0,300),
  lines:(Array.isArray(b.lines)?b.lines:[]).map(String).filter(x=>/^[\w+.-]{1,20}$/.test(x)).slice(0,10),hdr:o.hdr};c.line=c.lines.includes(b.line)?b.line:c.lines[0]||'';
  if(b.headers){try{const h=JSON.parse(b.headers);if(!h||typeof h!=='object'||Array.isArray(h))throw 0;c.hdr=enc(JSON.stringify(h))}catch{return bad(r,'هدرها باید JSON معتبر باشد')}}
  setCfg('sms',c);audit(q,'sms.config','');r.json(pubSms(c))});
app.post('/api/settings/sms/test',auth,need('admin'),async(q,r)=>{const m=mob((q.body||{}).to);if(!m)return bad(r,'شماره موبایل نامعتبر');
  try{const c=getCfg('sms');await sendSms(m,c.text||'تست پنل',c);r.json({ok:true})}catch(e){bad(r,e.message)}});
// ---------- hook از دایال‌پلن آسترسک ----------
// ---------- ثبت تماس (hook دایال‌پلن + رویداد AgentComplete آسترسک) ----------
async function recordCall(f){const d=db.prepare('SELECT id FROM calls WHERE uid=?').get(f.uid);let id;
  if(d){db.prepare("UPDATE calls SET caller=COALESCE(NULLIF(?,''),caller),agent=COALESCE(?,agent),queue=COALESCE(?,queue),dur=MAX(dur,?),score=COALESCE(?,score) WHERE id=?").run(f.caller||'',f.agent||null,f.queue||null,f.dur||0,f.score??null,d.id);id=d.id}
  else id=db.prepare('INSERT INTO calls(uid,ts,caller,agent,queue,dur,score) VALUES(?,?,?,?,?,?,?)').run(f.uid,Date.now(),f.caller||'',f.agent||null,f.queue||null,f.dur||0,f.score??null).lastInsertRowid;
  const row=db.prepare('SELECT * FROM calls WHERE id=?').get(id),c=getCfg('sms'),m=mob(row.caller);
  if(c.enabled&&m&&db.prepare("UPDATE calls SET sms='pending' WHERE id=? AND sms IS NULL").run(id).changes){let st='sent';try{await sendSms(m,c.text||'با تشکر از تماس شما.',c)}catch{st='fail'}db.prepare('UPDATE calls SET sms=? WHERE id=?').run(st,id)}}
function onAgentComplete(m){const uid=m.Uniqueid||m.UniqueID;if(!uid)return;recordCall({uid,caller:m.CallerIDNum||m.CallerIDnum||callerOf.get(uid)||'',agent:mext(m.Interface||m.Member)||null,queue:okQ(m.Queue)?m.Queue:null,dur:+m.TalkTime||0}).catch(()=>{})}
const hookOk=(q,b)=>(E.HOOK_ALLOW||'127.0.0.1,::1,::ffff:127.0.0.1').split(',').includes(q.socket.remoteAddress)&&eq(b.secret||'',E.HOOK_SECRET),UF=express.urlencoded({extended:false,limit:'4kb'});
app.post('/hook/agent',UF,(q,r)=>{const b=q.body||{};if(!hookOk(q,b))return r.sendStatus(403);const x=db.prepare('SELECT agent FROM calls WHERE uid=?').get(String(b.uid||'').slice(0,40));r.type('text/plain').send(x&&x.agent||'')});
app.post('/hook/call',UF,(q,r)=>{const b=q.body||{};if(!hookOk(q,b))return r.sendStatus(403);
  const uid=String(b.uid||'').slice(0,40);if(!uid)return r.sendStatus(400);const s=+b.score;r.sendStatus(200);
  recordCall({uid,caller:/^[+\d]{3,20}$/.test(b.caller||'')?b.caller:'',agent:((b.chan||'').match(/(\d{2,8})/)||[])[1],queue:okQ(b.queue)?b.queue:null,dur:parseInt(b.dur)||0,score:s>=1&&s<=5?s:null}).catch(()=>{})});
// ---------- CRM مایکروسافت Dynamics 365 (فقط‌خواندنی: تنها متد GET) ----------
let tok=null;const crmCache=new Map(),last10=n=>String(n).replace(/\D/g,'').slice(-10);
async function d365(p){const c=getCfg('crm');if(!c.enabled)return null;
  if(!tok||tok.exp<Date.now()){const r=await fetch(`https://login.microsoftonline.com/${encodeURIComponent(c.tenant)}/oauth2/v2.0/token`,{method:'POST',signal:AbortSignal.timeout(10000),headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:c.client,client_secret:dec(c.secret),scope:c.org+'/.default'})});
    if(!r.ok)throw new Error('احراز هویت Azure AD ناموفق: '+r.status);const j=await r.json();tok={t:j.access_token,exp:Date.now()+(j.expires_in-120)*1e3}}
  const r=await fetch(c.org+'/api/data/v9.2/'+p,{method:'GET',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{Authorization:'Bearer '+tok.t,Accept:'application/json','OData-Version':'4.0',Prefer:'odata.include-annotations="OData.Community.Display.V1.FormattedValue"'}});
  if(!r.ok)throw new Error('خطای Dynamics: '+r.status);return(await r.json()).value}
const SEL='$select=fullname,emailaddress1,mobilephone,telephone1,jobtitle,_parentcustomerid_value,contactid',pubCrm=c=>({enabled:!!c.enabled,org:c.org||'',tenant:c.tenant||'',client:c.client||'',has_secret:!!c.secret});
const shape=x=>({id:x.contactid,name:x.fullname,email:x.emailaddress1,mobile:x.mobilephone,phone:x.telephone1,job:x.jobtitle,company:x['_parentcustomerid_value@OData.Community.Display.V1.FormattedValue']||''});
async function crmLookup(n){const d=last10(n);if(d.length<7)return null;const k=crmCache.get(d);if(k&&k.exp>Date.now())return k.v;
  const rows=await d365(`contacts?${SEL}&$top=3&$filter=${encodeURIComponent(`contains(mobilephone,'${d}') or contains(telephone1,'${d}') or contains(telephone2,'${d}')`)}`);if(rows===null)return null;
  const v=rows.length?{...shape(rows[0]),more:rows.length-1}:{none:true};if(crmCache.size>2000)crmCache.clear();crmCache.set(d,{v,exp:Date.now()+3e5});return v}
const hist=n=>db.prepare("SELECT ts,agent,queue,dur,score,(SELECT name FROM users WHERE ext=calls.agent) an FROM calls WHERE caller LIKE ? ORDER BY ts DESC LIMIT 20").all('%'+last10(n));
const info=async n=>({crm:await crmLookup(n).catch(e=>({error:e.message})),history:hist(n)}),AG=['admin','supervisor','operator'];
app.get('/api/mycall',auth,need(...AG),async(q,r)=>{if(Date.now()-S.seen>3e4)await poll();S.seen=Date.now();const e=q.user.ext,c=e&&S.channels.find(c=>/^(PJSIP|SIP|IAX2)\//.test(c.Channel)&&chExt(c)===e);if(!c)return r.json({active:false});
  const n=[c.ConnectedLineNum,c.CallerIDNum].find(x=>x&&x!==e&&/^[+\d]{3,20}$/.test(x))||'';r.json({active:true,state:c.ChannelStateDesc,dur:c.Duration,caller:n,...(n?await info(n):{})})});
app.get('/api/lookup',auth,need(...AG),async(q,r)=>{const n=String(q.query.number||'');if(!/^[+\d\s-]{5,20}$/.test(n))return bad(r,'شماره نامعتبر');r.json(await info(n))});
app.get('/api/crm/search',auth,need(...AG),async(q,r)=>{const s=String(q.query.q||'').trim();if(s.length<2||s.length>40)return bad(r,'حداقل ۲ حرف');
  try{const f=/^[\d+\s-]{4,}$/.test(s)?`contains(mobilephone,'${last10(s)}') or contains(telephone1,'${last10(s)}')`:`contains(fullname,'${s.replace(/'/g,"''")}')`;
    r.json(((await d365(`contacts?${SEL}&$top=15&$filter=${encodeURIComponent(f)}`))||[]).map(shape))}catch(e){r.status(502).json({error:e.message})}});
app.put('/api/settings/crm',auth,need('admin'),(q,r)=>{const b=q.body||{},o=getCfg('crm');
  if(!/^https:\/\/[\w-]+\.crm\d*\.dynamics\.com$/i.test(b.org||''))return bad(r,'آدرس باید مثل https://ORG.crm4.dynamics.com باشد');
  if(!/^[\w.-]{3,80}$/.test(b.tenant||'')||!/^[0-9a-f-]{36}$/i.test(b.client||''))return bad(r,'Tenant یا Client ID نامعتبر');
  const c={enabled:!!b.enabled,org:b.org,tenant:b.tenant,client:b.client,secret:b.secret?enc(String(b.secret).slice(0,200)):o.secret};tok=null;crmCache.clear();setCfg('crm',c);audit(q,'crm.config','');r.json(pubCrm(c))});
app.post('/api/settings/crm/test',auth,need('admin'),async(q,r)=>{if(!getCfg('crm').enabled)return bad(r,'ابتدا فعال و ذخیره کنید');try{await d365('contacts?$select=fullname&$top=1');r.json({ok:true})}catch(e){bad(r,e.message)}});
// ---------- تلفن‌های Grandstream (HTTP API) ----------
const okIp=ip=>/^(\d{1,3}\.){3}\d{1,3}$/.test(ip||'')&&ip.split('.').every(x=>+x<256)&&!/^(127\.|0\.|169\.254\.|22[4-9]\.|2[3-5]\d\.)/.test(ip);
function gsReq(p,path,body,sid){return new Promise((ok,rej)=>{const x=(p.https?https:http).request({host:p.ip,port:p.https?443:80,path,method:body?'POST':'GET',rejectUnauthorized:false,timeout:8000,headers:{...(body?{'Content-Type':'application/x-www-form-urlencoded'}:{}),...(sid?{Cookie:'session_id='+sid}:{})}},res=>{let d='';res.on('data',c=>{if(d.length<2e5)d+=c});res.on('end',()=>{try{ok(JSON.parse(d))}catch{rej(new Error('پاسخ نامعتبر از تلفن'))}})});x.on('timeout',()=>x.destroy(new Error('timeout')));x.on('error',rej);x.end(body)})}
const gsC=new Map(),badReq=m=>Object.assign(new Error(m),{bad:1});
const gsSid=async(p,f)=>{const c=gsC.get(p.id);if(!f&&c&&c.exp>Date.now())return c.sid;const r=await gsReq(p,'/cgi-bin/dologin',`username=${encodeURIComponent(p.user)}&password=${encodeURIComponent(dec(p.pw))}`);if(r.response!=='success'||!r.body)throw new Error('ورود به تلفن ناموفق');gsC.set(p.id,{sid:r.body.sid,exp:Date.now()+18e4});return r.body.sid};
const gsDo=fn=>async(q,r)=>{const p=db.prepare('SELECT * FROM phones WHERE id=?').get(+q.params.id);if(!p)return r.status(404).json({error:'یافت نشد'});
  try{const run=async f=>fn(p,encodeURIComponent(await gsSid(p,f)),q.body||{});audit(q,'phone.'+q.path.split('/').pop(),p.name);let o=await run(false);if(o&&o.response==='error')o=await run(true);r.json(o)}catch(e){r.status(e.bad?400:502).json({error:e.message})}};
app.get('/api/phones',auth,need('admin'),(q,r)=>r.json(db.prepare('SELECT id,name,ip,https FROM phones').all()));
app.post('/api/phones',auth,need('admin'),(q,r)=>{const b=q.body||{};if(!okIp(b.ip)||!b.name||!b.user||!b.pw)return bad(r,'نام، IP معتبر، کاربر و رمز لازم است');
  try{db.prepare('INSERT INTO phones(name,ip,https,user,pw) VALUES(?,?,?,?,?)').run(String(b.name).slice(0,40),b.ip,b.https?1:0,String(b.user).slice(0,40),enc(String(b.pw).slice(0,100)))}catch{return bad(r,'این IP قبلاً ثبت شده')}r.json({ok:true})});
app.delete('/api/phones/:id',auth,need('admin'),(q,r)=>{db.prepare('DELETE FROM phones WHERE id=?').run(+q.params.id);gsC.delete(+q.params.id);r.json({ok:true})});
app.post('/api/phones/:id/info',auth,need('admin'),gsDo((p,s)=>gsReq(p,`/cgi-bin/api-get_line_status?sid=${s}`,null,s)));
app.post('/api/phones/:id/get',auth,need('admin'),gsDo((p,s,b)=>{if(!/^P\d{1,5}(:P\d{1,5})*$/.test(b.keys||''))throw badReq('کلیدها نامعتبر');return gsReq(p,`/cgi-bin/api.values.get?request=${b.keys}&sid=${s}`,null,s)}));
app.post('/api/phones/:id/set',auth,need('admin'),gsDo((p,s,b)=>{const e=Object.entries(b.values||{});if(!e.length||e.some(([k,v])=>!/^P\d{1,5}$/.test(k)||typeof v!=='string'||v.length>256))throw badReq('مقادیر نامعتبر');
  return gsReq(p,'/cgi-bin/api.values.post',e.map(([k,v])=>k+'='+encodeURIComponent(v)).join('&')+'&sid='+s,s)}));
app.post('/api/phones/:id/reboot',auth,need('admin'),gsDo((p,s)=>gsReq(p,`/cgi-bin/api-sys_operation?request=REBOOT&sid=${s}`,null,s)));
// ---------- فایل‌های صوتی (پرامپت‌ها) ----------
const SLOTS=['survey-prompt','agent-intro','thanks',...[0,1,2,3,4,5,6,7,8,9].map(d=>'digit-'+d)],SD=E.SOUND_DIR||'/sounds',sf=s=>`${SD}/panel-${s}.wav`;
const wavOk=b=>b.length>44&&b.toString('latin1',0,4)==='RIFF'&&b.toString('latin1',8,12)==='WAVE'&&b.readUInt16LE(20)===1&&b.readUInt16LE(22)===1&&[8000,16000].includes(b.readUInt32LE(24))&&b.readUInt16LE(34)===16;
app.get('/api/audio',auth,need('admin'),(q,r)=>r.json(Object.fromEntries(SLOTS.filter(s=>fs.existsSync(sf(s))).map(s=>[s,1]))));
app.get('/api/audio/:slot/file',auth,need('admin'),(q,r)=>SLOTS.includes(q.params.slot)?r.type('audio/wav').sendFile(`panel-${q.params.slot}.wav`,{root:SD},e=>e&&!r.headersSent&&r.sendStatus(404)):r.sendStatus(404));
app.put('/api/audio/:slot',auth,need('admin'),(q,r)=>{if(!SLOTS.includes(q.params.slot))return bad(r,'نامعتبر');const b=Buffer.from(String((q.body||{}).data||''),'base64');
  if(b.length>3e6||!wavOk(b))return bad(r,'فقط WAV تک‌کاناله 16-bit با نرخ 8000 یا 16000 مجاز است');
  try{fs.writeFileSync(sf(q.params.slot),b,{mode:0o644})}catch{return r.status(500).json({error:'نوشتن در پوشه‌ی صداها ممکن نیست (راهنما بخش ۷)'})}audit(q,'audio.up',q.params.slot);r.json({ok:true})});
app.delete('/api/audio/:slot',auth,need('admin'),(q,r)=>{if(SLOTS.includes(q.params.slot))try{fs.unlinkSync(sf(q.params.slot))}catch{}r.json({ok:true})});
app.use((e,q,r,n)=>r.status(400).json({error:'درخواست نامعتبر'}));
process.on('unhandledRejection',e=>console.error('unhandled:',e&&e.message));
connect();poll();const srv=app.listen(+E.PORT||3000,E.BIND||'0.0.0.0',()=>console.log('panel up'));srv.requestTimeout=15e3;srv.headersTimeout=1e4;srv.keepAliveTimeout=5e3;
process.on('SIGTERM',()=>{srv.close();try{db.close()}catch{}process.exit(0)});
