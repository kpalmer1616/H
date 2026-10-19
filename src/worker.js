const PACKS={pack5:{credits:5,cents:499},pack20:{credits:20,cents:1499},pack50:{credits:50,cents:2999}};
const PLANS={pro:{limit:25,cents:999},business:{limit:100,cents:1999}};
const encoder=new TextEncoder();
const json=(v,status=200,headers={})=>new Response(JSON.stringify(v),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers}});
const fail=(message,status=400)=>json({error:message},status);
const hex=b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const rand=()=>crypto.randomUUID();
async function digest(value){return hex(await crypto.subtle.digest('SHA-256',encoder.encode(value)));}
async function passwordHash(pass,salt){const key=await crypto.subtle.importKey('raw',encoder.encode(pass),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:encoder.encode(salt),iterations:210000,hash:'SHA-256'},key,256));}
function cookie(req){const m=(req.headers.get('cookie')||'').match(/(?:^|;\s*)qp_session=([^;]+)/);return m?m[1]:null;}
async function currentUser(req,env){const token=cookie(req);if(!token)return null;return await env.DB.prepare("SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at > datetime('now')").bind(await digest(token)).first();}
function sessionCookie(token,maxAge=604800){return `qp_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;}
async function createSession(env,id){const token=rand()+rand();await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,datetime('now','+7 days'))").bind(await digest(token),id).run();return sessionCookie(token);}
async function body(req){if(Number(req.headers.get('content-length')||0)>16000)throw Error('Request too large');return await req.json();}
const emailOk=e=>typeof e==='string'&&e.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const userView=u=>({email:u.email,plan:u.plan,status:u.subscription_status,monthlyLimit:u.monthly_limit,monthlyUsed:u.monthly_used,credits:u.credits,resetAt:u.reset_at});
function originOk(req){const origin=req.headers.get('origin');return !!origin&&origin===new URL(req.url).origin;}
async function stripeRequest(env,path,params){if(!env.STRIPE_SECRET_KEY)throw Error('Stripe is not configured');const res=await fetch('https://api.stripe.com/v1/'+path,{method:'POST',headers:{authorization:`Bearer ${env.STRIPE_SECRET_KEY}`,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(params)});const result=await res.json();if(!res.ok)throw Error(result.error?.message||'Stripe error');return result;}
async function stripeGet(env,path){const r=await fetch('https://api.stripe.com/v1/'+path,{headers:{authorization:`Bearer ${env.STRIPE_SECRET_KEY}`}});const data=await r.json();if(!r.ok)throw Error(data.error?.message||'Stripe error');return data;}
async function webhookVerified(req,env,raw){if(!env.STRIPE_WEBHOOK_SECRET)return false;const header=req.headers.get('stripe-signature')||'';const ts=header.match(/(?:^|,)t=(\d+)/)?.[1];const signatures=[...header.matchAll(/(?:^|,)v1=([0-9a-f]+)/g)].map(m=>m[1]);if(!ts||!signatures.length||Math.abs(Date.now()/1000-Number(ts))>300)return false;const key=await crypto.subtle.importKey('raw',encoder.encode(env.STRIPE_WEBHOOK_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);const sig=hex(await crypto.subtle.sign('HMAC',key,encoder.encode(ts+'.'+raw)));return signatures.some(s=>s===sig);}
async function webhook(req,env){const raw=await req.text();if(!(await webhookVerified(req,env,raw)))return fail('Invalid signature',400);const event=JSON.parse(raw);const exists=await env.DB.prepare('SELECT id FROM stripe_events WHERE id=?').bind(event.id).first();if(exists)return json({received:true});const obj=event.data.object;
// Apply the event and record its ID in one D1 transaction. A failed event can be retried by Stripe.
const statements=[];
if(event.type==='checkout.session.completed'&&obj.payment_status==='paid'&&obj.mode==='payment'){
 const kind=obj.metadata?.kind;const userId=obj.metadata?.user_id;const pack=PACKS[kind];
 if(pack&&userId&&obj.amount_total===pack.cents&&obj.currency==='usd')statements.push(env.DB.prepare('UPDATE users SET credits=credits+? WHERE id=?').bind(pack.credits,userId));
}
if(event.type==='checkout.session.completed'&&obj.mode==='subscription'){
 const userId=obj.metadata?.user_id;const subId=obj.subscription;const customer=obj.customer;
 if(userId&&subId)statements.push(env.DB.prepare('UPDATE users SET subscription_id=?,stripe_customer_id=? WHERE id=?').bind(subId,customer,userId));
}
if(['customer.subscription.created','customer.subscription.updated','customer.subscription.deleted'].includes(event.type)){
 const priceId=obj.items?.data?.[0]?.price?.id;const plan=priceId===env.STRIPE_PRICE_PRO?'pro':priceId===env.STRIPE_PRICE_BUSINESS?'business':null;
 const active=event.type!=='customer.subscription.deleted'&&['active','trialing'].includes(obj.status)&&!!plan;
 const uid=obj.metadata?.user_id;
 // Only subscriptions tied to a known user are allowed to change entitlements.
 if(uid)statements.push(env.DB.prepare('UPDATE users SET plan=?,subscription_status=?,monthly_limit=?,monthly_used=CASE WHEN subscription_id=? THEN monthly_used ELSE 0 END,subscription_id=?,stripe_customer_id=?,reset_at=? WHERE id=?').bind(active?plan:'none',obj.status,active?PLANS[plan].limit:0,obj.id,obj.id,obj.customer,obj.current_period_end?new Date(obj.current_period_end*1000).toISOString():null,uid));
}
if(event.type==='invoice.paid'&&obj.subscription){
 // New paid billing invoice replenishes the monthly allowance. Duplicate invoices are ignored by event ID.
 statements.push(env.DB.prepare("UPDATE users SET monthly_used=0 WHERE subscription_id=? AND subscription_status IN ('active','trialing')").bind(obj.subscription));
}
statements.push(env.DB.prepare('INSERT INTO stripe_events(id) VALUES(?)').bind(event.id));await env.DB.batch(statements);return json({received:true});}
async function route(req,env){const url=new URL(req.url);const path=url.pathname;if(path==='/api/stripe/webhook'&&req.method==='POST')return webhook(req,env);
if(!path.startsWith('/api/'))return env.ASSETS.fetch(req);
if(req.method==='POST'&&!originOk(req))return fail('Invalid origin',403);
if(path==='/api/register'&&req.method==='POST'){
 const b=await body(req);const email=String(b.email||'').trim().toLowerCase(),pass=b.password;
 if(!emailOk(email)||typeof pass!=='string'||pass.length<12||pass.length>128)return fail('Enter a valid email and password of at least 12 characters');
 const salt=rand(),hash=await passwordHash(pass,salt),id=rand();try{await env.DB.prepare('INSERT INTO users(id,email,password_hash,salt) VALUES(?,?,?,?)').bind(id,email,hash,salt).run();}catch{return fail('Email already registered',409);}
 return json({user:{email,plan:'none',monthlyLimit:0,monthlyUsed:0,credits:0}},200,{'set-cookie':await createSession(env,id)});
}
if(path==='/api/login'&&req.method==='POST'){
 const b=await body(req);const email=String(b.email||'').trim().toLowerCase();const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
 if(!u||typeof b.password!=='string'||await passwordHash(b.password,u.salt)!==u.password_hash)return fail('Invalid email or password',401);
 return json({user:userView(u)},200,{'set-cookie':await createSession(env,u.id)});
}
const u=await currentUser(req,env);if(!u)return fail('Please sign in',401);
if(path==='/api/me'&&req.method==='GET')return json({user:userView(u)});
if(path==='/api/logout'&&req.method==='POST'){const t=cookie(req);await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(t)).run();return json({ok:true},200,{'set-cookie':sessionCookie('',0)});}
if(path==='/api/quotes'&&req.method==='GET'){
 const q=await env.DB.prepare('SELECT id,customer_name,service,cost,price,margin,credit_source,created_at FROM quotes WHERE user_id=? ORDER BY created_at DESC LIMIT 50').bind(u.id).all();return json({quotes:q.results});
}
if(path==='/api/quotes'&&req.method==='POST'){
 const b=await body(req);const customer=String(b.customer||'').trim(),service=String(b.service||'').trim();
 const n=['hours','rate','materials','overhead','margin'].map(k=>Number(b[k]));
 if(!customer||customer.length>120||!service||service.length>120||n.some(x=>!Number.isFinite(x))||n.slice(0,4).some(x=>x<0||x>1000000)||n[4]<0||n[4]>90)return fail('Check quote details and margin (0–90%)');
 const [hours,rate,materials,overhead,margin]=n;const cost=Math.round((hours*rate+materials+overhead)*100)/100;const price=Math.round(cost/(1-margin/100)*100)/100;
 if(cost<=0||price>100000000)return fail('Enter positive, reasonable costs');
 // Atomic D1 update ensures concurrent requests cannot exceed allowances.
 const result=await env.DB.prepare(`UPDATE users SET monthly_used=CASE WHEN plan!='none' AND subscription_status IN ('active','trialing') AND monthly_used<monthly_limit THEN monthly_used+1 ELSE monthly_used END, credits=CASE WHEN plan!='none' AND subscription_status IN ('active','trialing') AND monthly_used<monthly_limit THEN credits ELSE credits-1 END WHERE id=? AND ((plan!='none' AND subscription_status IN ('active','trialing') AND monthly_used<monthly_limit) OR credits>0) RETURNING monthly_used,monthly_limit,credits`).bind(u.id).first();
 if(!result)return fail('No quote credits remaining. Buy credits or subscribe.',402);
 const source=u.plan!=='none'&&['active','trialing'].includes(u.subscription_status)&&u.monthly_used<u.monthly_limit?'subscription':'credit';const id=rand();
 try{await env.DB.prepare('INSERT INTO quotes(id,user_id,customer_name,service,hours,hourly_rate,materials,overhead,margin,cost,price,credit_source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,u.id,customer,service,hours,rate,materials,overhead,margin,cost,price,source).run();}
 catch(e){ // Refund a quota unit if the quote cannot be stored.
 await env.DB.prepare(source==='subscription'?'UPDATE users SET monthly_used=MAX(0,monthly_used-1) WHERE id=?':'UPDATE users SET credits=credits+1 WHERE id=?').bind(u.id).run();throw e;}
 return json({quote:{id,customer,service,cost,price,margin,source},balance:result});
}
if(path==='/api/checkout'&&req.method==='POST'){
 const b=await body(req);const sku=String(b.sku||'');const plan=PLANS[sku],pack=PACKS[sku];if(!plan&&!pack)return fail('Unknown product');
 const price=sku==='pro'?env.STRIPE_PRICE_PRO:sku==='business'?env.STRIPE_PRICE_BUSINESS:sku==='pack5'?env.STRIPE_PRICE_PACK5:sku==='pack20'?env.STRIPE_PRICE_PACK20:env.STRIPE_PRICE_PACK50;
 if(!price)return fail('Payment product not configured',503);
 const mode=plan?'subscription':'payment';const params={'mode':mode,'line_items[0][price]':price,'line_items[0][quantity]':'1','success_url':url.origin+'/dashboard.html?payment=success','cancel_url':url.origin+'/pricing.html?payment=cancel','client_reference_id':u.id,'metadata[user_id]':u.id,'metadata[kind]':sku};
 if(u.stripe_customer_id)params.customer=u.stripe_customer_id;else params.customer_email=u.email;
 if(plan){params['subscription_data[metadata][user_id]']=u.id;params['subscription_data[metadata][kind]']=sku;}
 if(pack&&u.stripe_customer_id)params.customer=u.stripe_customer_id;
 if(plan&&u.subscription_id&&['active','trialing'].includes(u.subscription_status))return fail('Manage your current subscription before starting another',409);
 const checkout=await stripeRequest(env,'checkout/sessions',params);return json({url:checkout.url});
}
if(path==='/api/billing-portal'&&req.method==='POST'){
 if(!u.stripe_customer_id)return fail('No billing account found',400);
 const portal=await stripeRequest(env,'billing_portal/sessions',{customer:u.stripe_customer_id,return_url:url.origin+'/dashboard.html'});return json({url:portal.url});
}
return fail('Not found',404);
}
export default {async fetch(req,env){try{return await route(req,env);}catch(err){console.error('QuotePilot error',err);return fail('Something went wrong. Please try again.',500);}}};
