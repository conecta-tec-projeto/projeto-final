'use strict';
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const app = express();
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('Configure SESSION_SECRET com pelo menos 32 caracteres em server/.env'); process.exit(1);
}
const pool = mysql.createPool({host:process.env.DB_HOST||'localhost',port:Number(process.env.DB_PORT||3306),user:process.env.DB_USER||'root',password:process.env.DB_PASSWORD||'',database:process.env.DB_NAME||'conectatec',waitForConnections:true,connectionLimit:10,decimalNumbers:true});
const MAX_PHOTOS=5;
const ready=(async()=>{
  await pool.query(`CREATE TABLE IF NOT EXISTS request_photos (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    request_id BIGINT UNSIGNED NOT NULL,
    mime VARCHAR(40) NOT NULL DEFAULT 'image/jpeg',
    data MEDIUMBLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE,
    INDEX idx_photo_request (request_id)
  )`);
  // Solicitações que o técnico "excluiu" da própria lista (o cliente continua vendo a dele).
  await pool.query(`CREATE TABLE IF NOT EXISTS request_hidden (
    request_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (request_id, user_id),
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  // Pagamento: forma "Cartão" e número de parcelas (atualiza bancos antigos sozinho).
  await pool.query("ALTER TABLE payments MODIFY method ENUM('Pix','Dinheiro','Transferência','Cartão','Outro') NOT NULL");
  const [col]=await pool.query("SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='payments' AND column_name='installments'");
  if(!Number(col[0].n))await pool.query('ALTER TABLE payments ADD COLUMN installments TINYINT UNSIGNED NOT NULL DEFAULT 1');
})();
const store = new MySQLStore({createDatabaseTable:true,clearExpired:true}, pool);
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use('/api/requests/:id/photos',express.json({limit:'3mb'}));
app.use(express.json({limit:'200kb'}));
app.use(session({name:'ct.sid',secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,rolling:true,store,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}}));
const auth = (req,res,next)=>req.session.uid?next():res.status(401).json({error:'Faça login para continuar.'});
const role = r=>(req,res,next)=>req.session.role===r?next():res.status(403).json({error:'Acesso não autorizado.'});
const fail=(res,msg,code=400)=>res.status(code).json({error:msg});
const one=async(sql,args=[])=>{const [rows]=await pool.execute(sql,args);return rows[0]||null};
const all=async(sql,args=[])=>{const [rows]=await pool.execute(sql,args);return rows};
const safe=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const own=async(id,uid)=>one('SELECT * FROM requests WHERE id=? AND (client_id=? OR technician_id=? OR directed_to=?)',[id,uid,uid,uid]);
// Quem pode VER um chamado: o cliente, o técnico responsável, o técnico direcionado
// e (antes do aceite) qualquer técnico, se o chamado estiver aberto e não for direcionado a outro.
const viewable=(id,uid,kind)=>one(kind==='tecnico'
  ?"SELECT * FROM requests WHERE id=? AND (client_id=? OR technician_id=? OR directed_to=? OR (status='enviada' AND technician_id IS NULL AND directed_to IS NULL))"
  :"SELECT * FROM requests WHERE id=? AND (client_id=? OR technician_id=? OR directed_to=?)",[id,uid,uid,uid]);
const summary=async(r)=>{const client=await one('SELECT id,name,email FROM users WHERE id=?',[r.client_id]);const tech=r.technician_id?await one('SELECT id,name,email FROM users WHERE id=?',[r.technician_id]):null;const q=await one('SELECT * FROM quotes WHERE request_id=? ORDER BY id DESC LIMIT 1',[r.id]);const fotos=await all('SELECT id FROM request_photos WHERE request_id=? ORDER BY id',[r.id]);const pay=await one('SELECT method,installments,amount,status FROM payments WHERE request_id=?',[r.id]);return {id:String(r.id),cliente:client,tecnico:tech,aparelho:r.device,descricao:r.description,categoria:r.category,tipo:r.service_type,prioridade:r.priority,prazo:r.desired_deadline,status:r.status,fotos:fotos.map(f=>f.id),diagnostico:r.diagnosis,criadoEm:new Date(r.created_at).getTime(),direcionadoPara:r.directed_to,pagamento:pay?{metodo:pay.method,parcelas:pay.installments,valor:pay.amount,status:pay.status}:null,orcamento:q?{id:q.id,peca:q.parts,mao:q.labor,total:q.parts+q.labor,prazo:q.estimated_days,diag:q.diagnosis,status:q.status}:null};};
const tooMany=(req,res)=>res.status(429).json({error:'Muitas tentativas. Aguarde alguns minutos e tente de novo.'});
// Só tentativas que FALHAM contam; abrir páginas (/auth/me) nunca conta.
app.use(['/api/auth/login','/api/auth/register','/api/auth/reset'],rateLimit({windowMs:15*60*1000,limit:30,skipSuccessfulRequests:true,standardHeaders:'draft-7',legacyHeaders:false,handler:tooMany}));
app.use('/api/auth/recover',rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:'draft-7',legacyHeaders:false,handler:tooMany}));
app.post('/api/auth/register',safe(async(req,res)=>{
  const {name,email,password,role:kind}=req.body;
  if(!String(name||'').trim()||!/^\S+@\S+\.\S+$/.test(email||'')||typeof password!=='string'||password.length<8||!['cliente','tecnico'].includes(kind))return fail(res,'Confira nome, e-mail, tipo e senha (mínimo 8 caracteres).');
  const phone=String(req.body.phone||'').trim(),address=String(req.body.address||'').trim();
  const digits=phone.replace(/\D/g,'');
  if(digits.length<10||digits.length>11)return fail(res,'Informe um telefone válido com DDD.');
  if(address.length<3)return fail(res,'Informe sua cidade e estado.');
  const tech=kind==='tecnico';
  const bio=tech?String(req.body.bio||'').trim().slice(0,2000):'';
  const specialties=tech&&Array.isArray(req.body.specialties)?req.body.specialties.filter(x=>typeof x==='string'&&x.trim()).map(x=>x.trim().slice(0,60)).slice(0,20):[];
  const okDays=['Seg','Ter','Qua','Qui','Sex','Sáb','Dom'];
  const days=tech&&Array.isArray(req.body.availableDays)?req.body.availableDays.filter(x=>okDays.includes(x)):[];
  const hash=await bcrypt.hash(password,12);
  try{
    const [r]=await pool.execute('INSERT INTO users (name,email,password_hash,role,phone,address,bio,specialties,available_days,portfolio) VALUES (?,?,?,?,?,?,?,?,?,?)',[String(name).trim(),email.trim().toLowerCase(),hash,kind,phone.slice(0,30),address.slice(0,255),bio,JSON.stringify(specialties),JSON.stringify(days),'[]']);
    req.session.uid=r.insertId;req.session.role=kind;
    res.status(201).json({user:{id:r.insertId,name:String(name).trim(),email:email.trim().toLowerCase(),role:kind}});
  }catch(e){if(e.code==='ER_DUP_ENTRY')return fail(res,'Este e-mail já está cadastrado.',409);throw e}
}));
app.post('/api/auth/login',safe(async(req,res)=>{const u=await one('SELECT * FROM users WHERE email=?',[(req.body.email||'').trim().toLowerCase()]);if(!u||!(await bcrypt.compare(req.body.password||'',u.password_hash)))return fail(res,'E-mail ou senha incorretos.',401);req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Erro de sessão'});req.session.uid=u.id;req.session.role=u.role;res.json({user:{id:u.id,name:u.name,email:u.email,role:u.role}})})}));
app.post('/api/auth/logout',auth,(req,res)=>req.session.destroy(()=>{res.clearCookie('ct.sid');res.json({ok:true})}));
app.get('/api/auth/me',auth,safe(async(req,res)=>{const u=await one('SELECT id,name,email,role,phone,address,bio,specialties,available_days,portfolio FROM users WHERE id=?',[req.session.uid]);res.json({user:u})}));
app.post('/api/auth/recover',safe(async(req,res)=>{const u=await one('SELECT id FROM users WHERE email=?',[(req.body.email||'').trim().toLowerCase()]);if(u){const token=crypto.randomBytes(32).toString('hex');await pool.execute('INSERT INTO password_resets (user_id,token_hash,expires_at) VALUES (?,?,DATE_ADD(NOW(), INTERVAL 30 MINUTE))',[u.id,crypto.createHash('sha256').update(token).digest('hex')]);if(process.env.NODE_ENV!=='production')console.log('LINK DE RECUPERAÇÃO (DESENVOLVIMENTO): http://localhost:'+ (process.env.PORT||3000) +'/03-recuperacao-senha.html?token='+token);}
res.json({message:'Se o e-mail existir, enviaremos instruções de recuperação. Em desenvolvimento, verifique o terminal do servidor.'})}));
app.post('/api/auth/reset',safe(async(req,res)=>{const {token,password}=req.body;if(typeof token!=='string'||!/^[a-f0-9]{64}$/.test(token)||typeof password!=='string'||password.length<8)return fail(res,'Link ou senha inválidos.');const hash=crypto.createHash('sha256').update(token).digest('hex');const r=await one('SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>NOW()',[hash]);if(!r)return fail(res,'Link inválido ou expirado.');await pool.execute('UPDATE users SET password_hash=? WHERE id=?',[await bcrypt.hash(password,12),r.user_id]);await pool.execute('UPDATE password_resets SET used_at=NOW() WHERE id=?',[r.id]);res.json({ok:true})}));
app.get('/api/users/technicians',auth,safe(async(req,res)=>res.json(await all("SELECT id,name,bio,specialties,portfolio FROM users WHERE role='tecnico' ORDER BY name"))));
app.get('/api/users/:id',auth,safe(async(req,res)=>{const u=await one('SELECT id,name,role,bio,specialties,portfolio FROM users WHERE id=?',[req.params.id]);if(!u||u.role!=='tecnico')return fail(res,'Técnico não encontrado.',404);res.json(u)}));
app.patch('/api/users/me',auth,safe(async(req,res)=>{const u=await one('SELECT role FROM users WHERE id=?',[req.session.uid]);const name=String(req.body.name||'').trim();if(!name)return fail(res,'Informe seu nome.');const specialties=Array.isArray(req.body.specialties)?req.body.specialties.filter(x=>typeof x==='string').slice(0,20):[];const portfolio=Array.isArray(req.body.portfolio)?req.body.portfolio.filter(x=>typeof x==='string'&&/^https:\/\//.test(x)).slice(0,12):[];await pool.execute('UPDATE users SET name=?,phone=?,address=?,bio=?,specialties=?,available_days=?,portfolio=? WHERE id=?',[name,String(req.body.phone||'').slice(0,30),String(req.body.address||'').slice(0,255),String(req.body.bio||'').slice(0,2000),JSON.stringify(u.role==='tecnico'?specialties:[]),JSON.stringify(u.role==='tecnico'&&Array.isArray(req.body.availableDays)?req.body.availableDays:[]),JSON.stringify(u.role==='tecnico'?portfolio:[]),req.session.uid]);res.json({ok:true})}));
app.get('/api/requests',auth,safe(async(req,res)=>{let rows;if(req.session.role==='cliente')rows=await all('SELECT * FROM requests WHERE client_id=? ORDER BY created_at DESC',[req.session.uid]);else rows=await all("SELECT * FROM requests WHERE (technician_id=? OR (status='enviada' AND (directed_to IS NULL OR directed_to=?))) AND id NOT IN (SELECT request_id FROM request_hidden WHERE user_id=?) ORDER BY created_at DESC",[req.session.uid,req.session.uid,req.session.uid]);res.json(await Promise.all(rows.map(summary)))}));
app.post('/api/requests',auth,role('cliente'),safe(async(req,res)=>{const {device,description,category,serviceType,priority,deadline,directedTo}=req.body;if(!String(device||'').trim())return fail(res,'Informe o tipo de aparelho.');
if(String(description||'').trim().length<10)return fail(res,'Descreva o problema com pelo menos 10 caracteres.');
if(!['Remoto','Presencial'].includes(serviceType))return fail(res,'Escolha o tipo de atendimento.');
if(!['Baixa','Média','Crítica'].includes(priority))return fail(res,'Escolha a prioridade.');
if(!String(deadline||'').trim())return fail(res,'Informe o prazo desejado.');if(directedTo){const t=await one("SELECT id FROM users WHERE id=? AND role='tecnico'",[directedTo]);if(!t)return fail(res,'Técnico escolhido não encontrado.');}const [r]=await pool.execute('INSERT INTO requests (client_id,directed_to,device,description,category,service_type,priority,desired_deadline) VALUES (?,?,?,?,?,?,?,?)',[req.session.uid,directedTo||null,String(device).slice(0,180),String(description).slice(0,5000),String(category||device).slice(0,100),serviceType,priority,String(deadline||'').slice(0,120)]);res.status(201).json({id:String(r.insertId)})}));
app.get('/api/requests/:id',auth,safe(async(req,res)=>{const r=await viewable(req.params.id,req.session.uid,req.session.role);if(!r)return fail(res,'Solicitação não encontrada.',404);res.json(await summary(r))}));
app.post('/api/requests/:id/accept',auth,role('tecnico'),safe(async(req,res)=>{const [r]=await pool.execute("UPDATE requests SET technician_id=?,status='aceita' WHERE id=? AND status='enviada' AND technician_id IS NULL AND (directed_to IS NULL OR directed_to=?)",[req.session.uid,req.params.id,req.session.uid]);if(!r.affectedRows)return fail(res,'Chamado indisponível ou já aceito.',409);res.json({ok:true})}));
app.post('/api/requests/:id/diagnosis',auth,role('tecnico'),safe(async(req,res)=>{const r=await one('SELECT * FROM requests WHERE id=? AND technician_id=?',[req.params.id,req.session.uid]);if(!r||!['aceita','diagnostico'].includes(r.status))return fail(res,'Diagnóstico indisponível.',409);const d=String(req.body.diagnosis||'').trim();if(!d)return fail(res,'Informe o diagnóstico.');await pool.execute("UPDATE requests SET diagnosis=?,status='diagnostico' WHERE id=?",[d,r.id]);res.json({ok:true})}));
app.post('/api/requests/:id/quotes',auth,role('tecnico'),safe(async(req,res)=>{const r=await one('SELECT * FROM requests WHERE id=? AND technician_id=?',[req.params.id,req.session.uid]);if(!r||r.status!=='diagnostico')return fail(res,'É necessário concluir o diagnóstico antes do orçamento.',409);const {parts,labor,days,diagnosis}=req.body;const p=Number(parts),l=Number(labor),d=Number(days);if(!Number.isFinite(p)||!Number.isFinite(l)||p<0||l<0||p+l<=0||!Number.isInteger(d)||d<1||!String(diagnosis||'').trim())return fail(res,'Orçamento inválido.');await pool.execute('INSERT INTO quotes (request_id,technician_id,parts,labor,estimated_days,diagnosis) VALUES (?,?,?,?,?,?)',[r.id,req.session.uid,p,l,d,String(diagnosis).slice(0,5000)]);await pool.execute("UPDATE requests SET status='aguardando_aprovacao',diagnosis=? WHERE id=?",[diagnosis,r.id]);res.json({ok:true})}));
app.post('/api/requests/:id/quote-decision',auth,role('cliente'),safe(async(req,res)=>{const r=await one('SELECT * FROM requests WHERE id=? AND client_id=?',[req.params.id,req.session.uid]);if(!r||r.status!=='aguardando_aprovacao')return fail(res,'Orçamento indisponível.',409);const q=await one("SELECT * FROM quotes WHERE request_id=? AND status='pendente' ORDER BY id DESC LIMIT 1",[r.id]);if(!q)return fail(res,'Orçamento não encontrado.',404);const accept=req.body.approve===true;await pool.execute('UPDATE quotes SET status=? WHERE id=?',[accept?'aprovado':'recusado',q.id]);await pool.execute('UPDATE requests SET status=?,technician_id=? WHERE id=?',[accept?'manutencao':'enviada',accept?q.technician_id:null,r.id]);res.json({ok:true})}));
app.post('/api/requests/:id/cancel',auth,role('cliente'),safe(async(req,res)=>{const [r]=await pool.execute("UPDATE requests SET status='cancelado' WHERE id=? AND client_id=? AND status IN ('enviada','aceita','diagnostico','orcamento','aguardando_aprovacao')",[req.params.id,req.session.uid]);if(!r.affectedRows)return fail(res,'Este chamado não pode ser cancelado.',409);res.json({ok:true})}));
app.post('/api/requests/:id/finish',auth,role('tecnico'),safe(async(req,res)=>{const [r]=await pool.execute("UPDATE requests SET status='concluido' WHERE id=? AND technician_id=? AND status='manutencao'",[req.params.id,req.session.uid]);if(!r.affectedRows)return fail(res,'Atendimento não pode ser concluído.',409);res.json({ok:true})}));
app.get('/api/requests/:id/messages',auth,safe(async(req,res)=>{if(!await own(req.params.id,req.session.uid))return fail(res,'Acesso negado.',403);res.json(await all('SELECT m.id,m.body,m.created_at,u.name AS sender_name,u.role AS sender_role FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.request_id=? ORDER BY m.id',[req.params.id]))}));
app.post('/api/requests/:id/messages',auth,safe(async(req,res)=>{const r=await own(req.params.id,req.session.uid);if(!r||!r.technician_id)return fail(res,'Conversa disponível após o aceite do chamado.',403);const body=String(req.body.body||'').trim();if(!body||body.length>2000)return fail(res,'Mensagem inválida.');await pool.execute('INSERT INTO messages (request_id,sender_id,body) VALUES (?,?,?)',[r.id,req.session.uid,body]);res.status(201).json({ok:true})}));
app.post('/api/requests/:id/payment',auth,role('cliente'),safe(async(req,res)=>{
  const r=await one("SELECT * FROM requests WHERE id=? AND client_id=? AND status IN ('manutencao','concluido')",[req.params.id,req.session.uid]);
  if(!r)return fail(res,'Atendimento indisponível.',409);
  const q=await one("SELECT * FROM quotes WHERE request_id=? AND status='aprovado' ORDER BY id DESC LIMIT 1",[r.id]);
  if(!q||!['Pix','Dinheiro','Transferência','Cartão','Outro'].includes(req.body.method))return fail(res,'Forma de pagamento inválida.');
  const parcelas=req.body.method==='Cartão'?Number(req.body.installments):1;
  if(!Number.isInteger(parcelas)||parcelas<1||parcelas>12)return fail(res,'Escolha de 1 a 12 parcelas.');
  await pool.execute("INSERT INTO payments (request_id,method,installments,amount,status) VALUES (?,?,?,?,'informado') ON DUPLICATE KEY UPDATE method=VALUES(method),installments=VALUES(installments),amount=VALUES(amount),status='informado'",[r.id,req.body.method,parcelas,q.parts+q.labor]);
  res.json({ok:true,message:'Pagamento registrado, não processado.'});
}));
// Excluir solicitação.
// Cliente: apaga de verdade (com mensagens, orçamentos, pagamento e fotos), exceto durante a manutenção.
// Técnico: remove só da própria lista; se já tinha aceitado/orçado, devolve o chamado ao cliente (sem técnico).
app.delete('/api/requests/:id',auth,safe(async(req,res)=>{
  const uid=req.session.uid;
  const conn=await pool.getConnection();
  try{
    await conn.beginTransaction();
    const [rows]=await conn.execute('SELECT * FROM requests WHERE id=? FOR UPDATE',[req.params.id]);
    const r=rows[0];
    if(req.session.role==='cliente'){
      if(!r||Number(r.client_id)!==uid){await conn.rollback();return fail(res,'Solicitação não encontrada.',404);}
      if(r.status==='manutencao'){await conn.rollback();return fail(res,'O serviço está em andamento. Aguarde o técnico concluir para excluir.',409);}
      await conn.execute('DELETE FROM messages WHERE request_id=?',[r.id]);
      await conn.execute('DELETE FROM payments WHERE request_id=?',[r.id]);
      await conn.execute('DELETE FROM quotes WHERE request_id=?',[r.id]);
      await conn.execute('DELETE FROM request_photos WHERE request_id=?',[r.id]);
      await conn.execute('DELETE FROM requests WHERE id=?',[r.id]);
    }else{
      const mine=r&&Number(r.technician_id)===uid;
      const open=r&&r.status==='enviada'&&r.technician_id===null&&(r.directed_to===null||Number(r.directed_to)===uid);
      if(!mine&&!open){await conn.rollback();return fail(res,'Solicitação não encontrada.',404);}
      if(mine&&r.status==='manutencao'){await conn.rollback();return fail(res,'O serviço está em andamento. Conclua o atendimento antes de excluir.',409);}
      if(mine&&['aceita','diagnostico','aguardando_aprovacao'].includes(r.status)){
        await conn.execute("UPDATE quotes SET status='recusado' WHERE request_id=? AND status='pendente'",[r.id]);
        await conn.execute("UPDATE requests SET technician_id=NULL,status='enviada' WHERE id=?",[r.id]);
      }
      await conn.execute('INSERT IGNORE INTO request_hidden (request_id,user_id) VALUES (?,?)',[r.id,uid]);
    }
    await conn.commit();
    res.json({ok:true});
  }catch(e){try{await conn.rollback();}catch(_){}throw e;}finally{conn.release();}
}));
// Técnico aceita o chamado, registra o diagnóstico e envia o orçamento (valor em R$) de uma só vez.
// Tudo em uma transação: se algo falhar, o chamado NÃO fica aceito pela metade.
app.post('/api/requests/:id/accept-and-quote',auth,role('tecnico'),safe(async(req,res)=>{
  const diagnosis=String(req.body.diagnosis||'').trim();
  const amount=typeof req.body.amount==='number'?req.body.amount:NaN;
  const days=req.body.days;
  if(!diagnosis)return fail(res,'Informe o diagnóstico.');
  if(diagnosis.length>5000)return fail(res,'Diagnóstico muito longo (máximo de 5000 caracteres).');
  if(!Number.isFinite(amount)||amount<=0)return fail(res,'Informe um valor do serviço válido, maior que R$ 0,00.');
  if(amount>1000000)return fail(res,'Valor acima do máximo permitido (R$ 1.000.000,00).');
  if(!Number.isInteger(days)||days<1||days>365)return fail(res,'Informe o prazo estimado em dias úteis (de 1 a 365).');
  const value=Math.round(amount*100)/100,uid=req.session.uid;
  const conn=await pool.getConnection();
  try{
    await conn.beginTransaction();
    const [rows]=await conn.execute('SELECT * FROM requests WHERE id=? FOR UPDATE',[req.params.id]);
    const r=rows[0];
    if(!r){await conn.rollback();return fail(res,'Solicitação não encontrada.',404);}
    const mine=Number(r.technician_id)===uid&&['aceita','diagnostico'].includes(r.status);
    const open=r.status==='enviada'&&r.technician_id===null&&(r.directed_to===null||Number(r.directed_to)===uid);
    if(!mine&&!open){await conn.rollback();return fail(res,'Chamado indisponível ou já aceito.',409);}
    await conn.execute('INSERT INTO quotes (request_id,technician_id,parts,labor,estimated_days,diagnosis) VALUES (?,?,0,?,?,?)',[r.id,uid,value,days,diagnosis]);
    await conn.execute("UPDATE requests SET technician_id=?,status='aguardando_aprovacao',diagnosis=? WHERE id=?",[uid,diagnosis,r.id]);
    await conn.commit();
    res.json({ok:true});
  }catch(e){try{await conn.rollback();}catch(_){}throw e;}finally{conn.release();}
}));
// Fotos do aparelho: o cliente envia (JPEG já reduzido pelo navegador); cliente e técnicos autorizados visualizam.
app.post('/api/requests/:id/photos',auth,role('cliente'),safe(async(req,res)=>{
  const r=await one('SELECT id,status FROM requests WHERE id=? AND client_id=?',[req.params.id,req.session.uid]);
  if(!r)return fail(res,'Solicitação não encontrada.',404);
  if(r.status!=='enviada')return fail(res,'Só é possível anexar fotos enquanto a solicitação está aberta.',409);
  const total=Number((await one('SELECT COUNT(*) AS n FROM request_photos WHERE request_id=?',[r.id])).n);
  if(total>=MAX_PHOTOS)return fail(res,'Limite de '+MAX_PHOTOS+' fotos por solicitação.',409);
  const m=/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body.image||''));
  if(!m)return fail(res,'Imagem inválida. Envie uma foto em JPEG.');
  const buf=Buffer.from(m[1],'base64');
  if(buf.length<100||buf.length>2*1024*1024||buf[0]!==0xFF||buf[1]!==0xD8||buf[2]!==0xFF)return fail(res,'Imagem inválida ou maior que 2 MB.');
  const [ins]=await pool.execute('INSERT INTO request_photos (request_id,mime,data) VALUES (?,?,?)',[r.id,'image/jpeg',buf]);
  res.status(201).json({id:ins.insertId});
}));
app.get('/api/photos/:id',auth,safe(async(req,res)=>{
  const p=await one('SELECT request_id,mime,data FROM request_photos WHERE id=?',[req.params.id]);
  if(!p||!await viewable(p.request_id,req.session.uid,req.session.role))return fail(res,'Foto não encontrada.',404);
  res.set({'Content-Type':p.mime,'Cache-Control':'private, max-age=3600','Content-Disposition':'inline'});
  res.send(p.data);
}));
app.use('/server',(req,res)=>res.status(404).end());
app.use(express.static(path.resolve(__dirname,'..'),{extensions:['html'],dotfiles:'deny'}));
app.get('/',(req,res)=>res.redirect('/01-login.html'));
app.use('/api',(req,res)=>fail(res,'Rota não encontrada.',404));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Erro interno do servidor.'})});
const port=Number(process.env.PORT||3000);ready.then(()=>app.listen(port,()=>console.log(`ConectaTec em http://localhost:${port}`))).catch(e=>{console.error('Falha ao preparar o banco de dados (confira se o schema.sql foi executado):',e.message);process.exit(1)});
