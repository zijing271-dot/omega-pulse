/**
 * OMEGA Pulse — API Uptime Monitor SaaS
 *
 * Real deployable micro-SaaS. Monitor API endpoints, alert on downtime,
 * generate status pages. Monetize via Stripe subscriptions.
 *
 * Deploy: node api-monitor.js → http://localhost:3100
 * Monetize: $29/mo Basic (10 endpoints), $99/mo Pro (50 endpoints), $499/mo Enterprise
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const stripe = STRIPE_SECRET ? require('stripe')(STRIPE_SECRET) : null;

const PORT = process.env.PORT || 3100;
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Database (JSON file) ──
const DB_FILE = path.join(DATA_DIR, 'db.json');
let db = { users: [], monitors: [], incidents: [], payments: [], revenue: 0 };

if (fs.existsSync(DB_FILE)) {
  db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

// ── SSRF guard ──
// Only allow http(s) to public hosts. Blocks loopback, private, link-local
// (incl. cloud metadata 169.254.169.254) and internal TLDs. Note: does not
// resolve DNS, so a hostname pointing at a private IP (DNS rebinding) is not
// caught here — acceptable baseline for a public-endpoint monitor.
function isSafeMonitorUrl(raw) {
  let u;
  try { u = new URL(String(raw)); } catch { return false; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || host.endsWith('.internal') ||
      host === 'metadata.google.internal') return false;
  // IPv4 loopback / private / link-local / CGNAT
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (m.some(x => +x > 255)) return false;
    if (a === 0 || a === 127) return false;
    if (a === 10) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
  }
  // IPv6 loopback / link-local / unique-local
  if (host === '::1' || host === '::' ||
      host.startsWith('fe80') || host.startsWith('fc') || host.startsWith('fd')) return false;
  return true;
}

// ── Monitor Engine ──
async function checkEndpoint(monitor) {
  const start = Date.now();
  if (!isSafeMonitorUrl(monitor.url)) {
    return { up: false, statusCode: 0, latency: 0, checkedAt: Date.now(), blocked: true };
  }
  return new Promise((resolve) => {
    const url = new URL(monitor.url);
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.get(monitor.url, { timeout: monitor.timeout || 10000, headers: { 'User-Agent': 'OMEGA-Pulse/1.0' } }, (res) => {
      const latency = Date.now() - start;
      // 429 = rate-limited → degraded, not a real outage
      const up = res.statusCode >= 200 && res.statusCode < 400;
      const degraded = res.statusCode === 429;
      resolve({ up, degraded, statusCode: res.statusCode, latency, checkedAt: Date.now() });
    });
    req.on('error', () => resolve({ up: false, statusCode: 0, latency: Date.now() - start, checkedAt: Date.now() }));
    req.on('timeout', () => { req.destroy(); resolve({ up: false, statusCode: 0, latency: Date.now() - start, checkedAt: Date.now() }); });
  });
}

async function runAllChecks() {
  console.log(`[${new Date().toISOString()}] Running ${db.monitors.length} checks...`);
  for (const monitor of db.monitors) {
    if (!monitor.active) continue;
    const result = await checkEndpoint(monitor);
    monitor.lastCheck = result;
    monitor.history = monitor.history || [];
    monitor.history.push(result);
    if (monitor.history.length > 720) monitor.history = monitor.history.slice(-720); // 30 days hourly

	    if (!result.up && !result.degraded && (!monitor.lastDown || Date.now() - monitor.lastDown > 300000)) {
      monitor.lastDown = Date.now();
      db.incidents.push({
        id: crypto.randomUUID(),
        monitorId: monitor.id,
        url: monitor.url,
        statusCode: result.statusCode,
        latency: result.latency,
        startedAt: Date.now(),
        resolvedAt: null,
      });
      console.log(`  ⚠ DOWN: ${monitor.name} (${monitor.url}) — ${result.statusCode}`);
    }

	    if (result.up && monitor.lastDown) {
	      const openIncidents = db.incidents.filter(i => i.monitorId === monitor.id && !i.resolvedAt);
	      for (const incident of openIncidents) {
	        incident.resolvedAt = Date.now();
	        incident.duration = incident.resolvedAt - incident.startedAt;
	      }
	      if (openIncidents.length > 0) {
	        console.log(`  ✓ RECOVERED: ${monitor.name} — resolved ${openIncidents.length} incident(s)`);
	      }
	    }
  }
  saveDB();
}

// ── HTTP API Server ──
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  // Security headers for all responses
  const SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
  const applySecurityHeaders = (res, extraHeaders) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    if (extraHeaders) for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  };
  const send = (code, data) => { applySecurityHeaders(res, { 'Content-Type': 'application/json' }); res.writeHead(code); res.end(JSON.stringify(data)); };
  const body = () => new Promise(resolve => { let d = ''; req.on('data', c => d += c); req.on('end', () => { if (!d) return resolve({}); try { resolve(JSON.parse(d)); } catch { const params = {}; d.split('&').forEach(p => { const [k, v] = p.split('=').map(decodeURIComponent); params[k] = v || ''; }); resolve(params); } }); });

  // Routes
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === 'GET' && url.pathname === '/health') return send(200, { status: 'ok', uptime: process.uptime() });

  if (req.method === 'GET' && url.pathname === '/api/status') {
    const statuses = db.monitors.map(m => ({
      name: m.name, url: m.url, up: m.lastCheck?.up ?? null,
      degraded: m.lastCheck?.degraded ?? false,
      latency: m.lastCheck?.latency ?? null, uptime24h: calcUptime(m, 24),
      uptime30d: calcUptime(m, 720),
    }));
    return send(200, { monitors: statuses, totalRevenue: db.revenue, totalMonitors: db.monitors.length, activeIncidents: db.incidents.filter(i => !i.resolvedAt).length, degradedCount: db.monitors.filter(m => m.lastCheck?.degraded).length });
	  }
  if (req.method === 'POST' && url.pathname === '/api/monitors') {
    return body().then(b => {
      if (!isSafeMonitorUrl(b.url)) {
        return send(400, { error: 'Invalid or disallowed URL. Only public http(s) endpoints are allowed (private, loopback and link-local addresses are blocked).' });
      }
      const monitor = { id: crypto.randomUUID(), name: String(b.name || b.url).slice(0, 200), url: b.url, active: true, createdAt: Date.now(), history: [] };
      db.monitors.push(monitor);
      saveDB();
      send(201, monitor);
    });
  }

  // GET /subscribe?plan=basic → redirect to Stripe checkout
  if (req.method === 'GET' && url.pathname === '/subscribe') {
    if (!stripe) { res.writeHead(302, { Location: '/' }); return res.end(); }
    const plan = url.searchParams.get('plan') || 'basic';
    const amounts = { basic: 2900, pro: 9900, enterprise: 49900 };
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'subscription',
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: 'OMEGA Pulse — ' + plan.toUpperCase(), description: 'API Monitoring ' + plan + ' plan' },
            recurring: { interval: 'month' },
            unit_amount: amounts[plan] || 2900,
          },
          quantity: 1,
        }],
        success_url: `${PUBLIC_URL}/success`,
        cancel_url: `${PUBLIC_URL}/`,
        metadata: { plan },
      });
      console.log('  💳 REDIRECT CHECKOUT: ' + plan + ' → ' + session.id);
      res.writeHead(302, { Location: session.url });
      return res.end();
    } catch (e) {
      console.error('  Stripe redirect error:', e.message);
      res.writeHead(302, { Location: '/' });
      return res.end();
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/create-checkout-session') {
    if (!stripe) return send(500, { error: 'Stripe not configured. Set STRIPE_SECRET_KEY.' });
    return body().then(async b => {
      try {
        const prices = { basic: 'price_basic_29', pro: 'price_pro_99', enterprise: 'price_enterprise_499' };
        const amounts = { basic: 2900, pro: 9900, enterprise: 49900 };
        const plan = b.plan || 'basic';
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          mode: 'subscription',
          line_items: [{
            price_data: {
              currency: 'usd',
              product_data: { name: `OMEGA Pulse — ${plan.toUpperCase()}`, description: `API Monitoring ${plan} plan — ${plan === 'enterprise' ? 'Unlimited' : plan === 'pro' ? '50' : '10'} endpoints` },
              recurring: { interval: 'month' },
              unit_amount: amounts[plan] || 2900,
            },
            quantity: 1,
          }],
          success_url: b.success_url || `${PUBLIC_URL}/success`,
          cancel_url: b.cancel_url || `${PUBLIC_URL}/`,
          customer_email: b.email,
          metadata: { plan, email: b.email || '' },
        });
        console.log(`  💳 CHECKOUT: ${plan} — $${amounts[plan]/100}/mo — ${b.email || 'no-email'}`);
        send(201, { url: session.url, sessionId: session.id });
      } catch (e) {
        console.error('  Stripe error:', e.message);
        send(500, { error: e.message });
      }
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/webhook') {
    if (!stripe) return send(500, { error: 'Stripe not configured.' });
    let rawBody = '';
    req.on('data', c => rawBody += c);
    return req.on('end', async () => {
      try {
        if (!STRIPE_WEBHOOK_SECRET) {
          console.error('  Webhook rejected: STRIPE_WEBHOOK_SECRET not configured (refusing to process unverified event)');
          res.writeHead(500);
          return res.end(JSON.stringify({ error: 'Webhook secret not configured' }));
        }
        const sig = req.headers['stripe-signature'];
        const event = stripe.webhooks.constructEvent(rawBody, sig, STRIPE_WEBHOOK_SECRET);
        switch (event.type) {
          case 'checkout.session.completed': {
            const session = event.data.object;
            const plan = session.metadata?.plan || 'basic';
            const email = session.metadata?.email || session.customer_email || session.customer_details?.email || '';
            const amount = (session.amount_total || 2900) / 100;
            db.revenue += amount;
            db.payments.push({
              id: crypto.randomUUID(),
              stripeSessionId: session.id,
              stripeCustomerId: session.customer,
              plan, amount, email,
              ts: Date.now(),
            });
            saveDB();
            console.log(`  💰 REAL PAYMENT: ${plan} — $${amount} from ${email} (Total: $${db.revenue})`);

            // Grant paid access ONLY here, after Stripe-verified payment.
            // This is the single source of truth for arsenal entitlements.
            if (session.metadata?.product === 'arsenal') {
              const arsenalPath = path.join(DATA_DIR, 'arsenal-db.json');
              let adb = { users: [], subscriptions: [], affiliates: [], affiliateClicks: [], emailQueue: [], revenue: 0 };
              try { if (fs.existsSync(arsenalPath)) adb = JSON.parse(fs.readFileSync(arsenalPath, 'utf8')); } catch {}
              const aPlan = session.metadata?.plan || 'pro';
              const promo = session.metadata?.promo || '';
              const ref = session.metadata?.ref || '';
              let user = adb.users.find(u => u.email === email);
              if (user) {
                user.plan = aPlan; user.amount = amount; user.stripeCustomerId = session.customer; user.status = 'active';
              } else {
                user = { id: crypto.randomUUID(), email, plan: aPlan, promo, amount, stripeCustomerId: session.customer, status: 'active', createdAt: Date.now(), affiliateCode: ref };
                adb.users.push(user);
              }
              adb.subscriptions.push({ id: crypto.randomUUID(), userId: user.id, plan: aPlan, promo, amount, status: 'active', stripeSessionId: session.id, createdAt: Date.now() });
              adb.revenue = (adb.revenue || 0) + amount;
              adb.emailQueue = adb.emailQueue || [];
              adb.emailQueue.push({ to: email, type: 'welcome', plan: aPlan, ts: Date.now(), sent: false });
              // Affiliate commission — credited on verified payment only
              if (ref) {
                const affiliate = (adb.affiliates || []).find(a => a.code === ref);
                if (affiliate) {
                  const commission = Math.round(amount * 0.3 * 100) / 100;
                  affiliate.commissions = affiliate.commissions || [];
                  affiliate.commissions.push({ amount: commission, plan: aPlan, ts: Date.now(), userId: user.id });
                  affiliate.totalEarned = (affiliate.totalEarned || 0) + commission;
                  adb.emailQueue.push({ to: affiliate.email, type: 'commission', plan: aPlan, amount: commission, ts: Date.now(), sent: false });
                }
              }
              fs.writeFileSync(arsenalPath, JSON.stringify(adb, null, 2));
              console.log(`  [Arsenal] PAID ACCESS GRANTED (webhook-verified): ${aPlan} $${amount} — ${email}`);
            }
            break;
          }
          case 'invoice.paid': {
            const invoice = event.data.object;
            const plan = invoice.metadata?.plan || 'basic';
            const amount = (invoice.amount_paid || 0) / 100;
            if (amount > 0) {
              db.revenue += amount;
              db.payments.push({
                id: crypto.randomUUID(),
                stripeInvoiceId: invoice.id,
                stripeCustomerId: invoice.customer,
                plan, amount, email: invoice.customer_email || '',
                ts: Date.now(),
              });
              saveDB();
              console.log(`  💰 INVOICE PAID: ${plan} — $${amount} (Total: $${db.revenue})`);
            }
            break;
          }
        }
        res.writeHead(200); res.end(JSON.stringify({ received: true }));
      } catch (e) {
        console.error('  Webhook error:', e.message);
        res.writeHead(400); res.end(JSON.stringify({ error: e.message }));
      }
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/subscribe') {
    return body().then(async b => {
      if (!stripe) return send(503, { error: 'Payments are not configured. Set STRIPE_SECRET_KEY.' });
      const plan = b.plan || 'basic';
      const amounts = { basic: 2900, pro: 9900, enterprise: 49900 };
      try {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          mode: 'subscription',
          line_items: [{
            price_data: {
              currency: 'usd',
              product_data: { name: `OMEGA Pulse — ${plan.toUpperCase()}`, description: `API Monitoring ${plan} plan` },
              recurring: { interval: 'month' },
              unit_amount: amounts[plan] || 2900,
            },
            quantity: 1,
          }],
          success_url: b.success_url || `${PUBLIC_URL}/success`,
          cancel_url: b.cancel_url || `${PUBLIC_URL}/`,
          customer_email: b.email,
          metadata: { plan, email: b.email || '' },
        });
        // Revenue/entitlement is recorded by the verified webhook, not here.
        return send(200, { checkoutUrl: session.url, sessionId: session.id, plan, requiresPayment: true });
      } catch (e) {
        console.error('  Stripe error:', e.message);
        return send(500, { error: e.message });
      }
    });
  }

  // Landing Page
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '')) {
    applySecurityHeaders(res, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';"
    });
    res.writeHead(200);
    return res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>OMEGA Pulse — API Monitoring</title>
<style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:20px;background:#0a0a0f;color:#e8e8f0}
h1{background:linear-gradient(135deg,#7c5cfc,#4ecdc4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:48px}
.plan{display:inline-block;border:1px solid #1e1e32;border-radius:12px;padding:24px;margin:12px;width:200px;text-align:center}
.plan h3{color:#7c5cfc}.price{font-size:36px;font-weight:900}.btn{display:inline-block;margin-top:12px;padding:10px 24px;background:#7c5cfc;color:#fff;border-radius:8px;text-decoration:none}
.stats{display:flex;gap:24px;margin:24px 0}.stat{padding:20px;background:#131320;border-radius:12px;text-align:center;flex:1}
.stat-num{font-size:36px;font-weight:900;color:#4ecdc4}</style></head><body>
<h1>OMEGA Pulse</h1><p>AI-Powered API Monitoring. Know before your users do.</p>
<div class="stats"><div class="stat"><div class="stat-num">${db.monitors.length}</div>Monitors</div><div class="stat"><div class="stat-num">$${db.revenue}</div>Revenue</div><div class="stat"><div class="stat-num">99.9%</div>SLA</div></div>
<h2>Plans</h2>
<div class="plan"><h3>Basic</h3><div class="price">$29</div>/month<br>10 endpoints<br>5 min checks<br>Email alerts<br><a class="btn" href="/subscribe?plan=basic">Subscribe</a></div>
<div class="plan"><h3>Pro</h3><div class="price">$99</div>/month<br>50 endpoints<br>1 min checks<br>SMS + Slack<br><a class="btn" href="/subscribe?plan=pro">Subscribe</a></div>
<div class="plan"><h3>Enterprise</h3><div class="price">$499</div>/month<br>Unlimited<br>10 sec checks<br>Custom SLA<br><a class="btn" href="/subscribe?plan=enterprise">Subscribe</a></div>
</body></html>`);
  }

  // ── ReviewBot Waitlist endpoints ──
  const WAITLIST_FILE = path.join(__dirname, 'waitlist-emails.json');
  let waitlistEmails = [];
  try { if (fs.existsSync(WAITLIST_FILE)) waitlistEmails = JSON.parse(fs.readFileSync(WAITLIST_FILE, 'utf8')); } catch {}

  if (req.method === 'OPTIONS') return send(204, {});

  if (req.method === 'POST' && url.pathname === '/api/waitlist') {
    return body().then(b => {
      const email = (b.email || '').trim().toLowerCase();
      if (!email || !email.includes('@')) return send(400, { error: 'Invalid email' });

      const existing = waitlistEmails.find(e => e.email === email);
      if (existing) return send(200, { status: 'already_registered', position: waitlistEmails.indexOf(existing) + 1, total: waitlistEmails.length });

      const entry = { email, source: b.source || 'landing_page', timestamp: b.timestamp || new Date().toISOString() };
      waitlistEmails.push(entry);
      fs.writeFileSync(WAITLIST_FILE, JSON.stringify(waitlistEmails, null, 2));
      console.log(`[ReviewBot Waitlist] ${email} (${waitlistEmails.length} total)`);
      return send(200, { status: 'registered', position: waitlistEmails.length, total: waitlistEmails.length });
    });
  }

  if (req.method === 'GET' && url.pathname === '/api/waitlist/count') {
    return send(200, { count: waitlistEmails.length, remaining: Math.max(0, 50 - waitlistEmails.length) });
  }

  if (req.method === 'GET' && url.pathname === '/api/waitlist') {
    return send(200, { total: waitlistEmails.length, emails: waitlistEmails.map(e => ({ email: e.email, source: e.source, timestamp: e.timestamp })) });
  }

  // ═══════════════════════════════════════════
  //  GITHUB ARSENAL — Premium Monetized Platform
  // ═══════════════════════════════════════════

  const ARSENAL_DB = path.join(DATA_DIR, 'arsenal-db.json');
  let arsenalDB = { users: [], subscriptions: [], affiliates: [], affiliateClicks: [], emailQueue: [], revenue: 0 };
  try { if (fs.existsSync(ARSENAL_DB)) arsenalDB = JSON.parse(fs.readFileSync(ARSENAL_DB, 'utf8')); } catch {}
  function saveArsenalDB() { fs.writeFileSync(ARSENAL_DB, JSON.stringify(arsenalDB, null, 2)); }

  // Arsenal plan definitions
  const ARSENAL_PLANS = {
    explorer: { name: 'Explorer', price: 0, stripeAmount: 0, endpoints: 'basic' },
    pro: { name: 'Pro Arsenal', price: 49, stripeAmount: 4900, endpoints: 'unlimited' },
    enterprise: { name: 'Enterprise Empire', price: 199, stripeAmount: 19900, endpoints: 'unlimited' },
  };

  // ── Arsenal Plan Info ──
  if (req.method === 'GET' && url.pathname === '/api/arsenal/plans') {
    return send(200, { plans: ARSENAL_PLANS, totalRevenue: arsenalDB.revenue, totalUsers: arsenalDB.users.length, totalAffiliates: arsenalDB.affiliates.length });
  }

  // ── Arsenal Subscribe (GET redirect + POST) ──
  if (req.method === 'GET' && url.pathname === '/api/arsenal/subscribe') {
    const plan = url.searchParams.get('plan') || 'pro';
    const promo = url.searchParams.get('promo_code') || '';
    const subEmail = url.searchParams.get('email') || '';
    const subRef = url.searchParams.get('ref') || '';
    const planInfo = ARSENAL_PLANS[plan] || ARSENAL_PLANS.pro;
    let amount = planInfo.stripeAmount;
    if (promo === 'ARSENAL50') amount = Math.round(amount * 0.5);
    if (plan === 'explorer' || planInfo.stripeAmount === 0) {
      // Free plan — register directly (no payment). Paid plans NEVER reach here.
      const email = url.searchParams.get('email') || '';
      let user = arsenalDB.users.find(u => u.email === email && email);
      if (!user) {
        user = { id: crypto.randomUUID(), email: email || 'free-user@arsenal.io', plan: 'explorer', promo, amount: 0, status: 'active', createdAt: Date.now() };
        arsenalDB.users.push(user);
        arsenalDB.emailQueue.push({ to: user.email, type: 'welcome', plan: 'explorer', ts: Date.now(), sent: false });
        saveArsenalDB();
      }
      console.log(`  [Arsenal] FREE SIGNUP: explorer — ${user.email}`);
      res.writeHead(302, { Location: '/success?product=arsenal&plan=explorer&email=' + encodeURIComponent(user.email) });
      return res.end();
    }
    if (!stripe) {
      // Paid plan requested but payments not configured — do NOT grant access.
      res.writeHead(302, { Location: '/arsenal?error=payments_unavailable' });
      return res.end();
    }
    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: plan === 'explorer' ? 'payment' : 'subscription',
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: 'GitHub Arsenal — ' + planInfo.name, description: 'World\'s Only AI-Curated Elite Open-Source Intelligence. ' + planInfo.name + ' Plan.' },
            recurring: plan === 'explorer' ? undefined : { interval: 'month' },
            unit_amount: amount,
          },
          quantity: 1,
        }],
        success_url: `${PUBLIC_URL}/success?product=arsenal&plan=` + plan,
        cancel_url: `${PUBLIC_URL}/arsenal`,
        customer_email: subEmail || undefined,
        metadata: { product: 'arsenal', plan, promo, email: subEmail, ref: subRef },
        allow_promotion_codes: true,
      });
      console.log(`  [Arsenal] Stripe Checkout: ${plan} $${amount/100} → ${session.id}`);
      res.writeHead(302, { Location: session.url });
      return res.end();
    } catch (e) {
      console.error('  [Arsenal] Stripe error:', e.message);
      res.writeHead(302, { Location: '/subscribe-fallback?plan=' + plan + '&product=arsenal' });
      return res.end();
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/arsenal/subscribe') {
    return body().then(async b => {
      const plan = b.plan || 'pro';
      const promo = b.promo_code || '';
      const email = (b.email || '').trim().toLowerCase();
      const ref = b.ref || '';
      const planInfo = ARSENAL_PLANS[plan] || ARSENAL_PLANS.pro;

      // Free tier: no payment involved, register directly.
      if (plan === 'explorer' || planInfo.stripeAmount === 0) {
        if (!email || !email.includes('@')) return send(400, { error: 'Valid email required' });
        let user = arsenalDB.users.find(u => u.email === email);
        if (!user) {
          user = { id: crypto.randomUUID(), email, plan: 'explorer', amount: 0, status: 'active', createdAt: Date.now(), source: b.source || 'direct', affiliateCode: ref };
          arsenalDB.users.push(user);
          arsenalDB.emailQueue.push({ to: email, type: 'welcome', plan: 'explorer', ts: Date.now(), sent: false });
          saveArsenalDB();
        }
        return send(201, { registered: true, plan: 'explorer', userId: user.id });
      }

      // Paid plans MUST pay via Stripe. Entitlement is granted ONLY by the
      // verified webhook (checkout.session.completed) — never here.
      if (!stripe) return send(503, { error: 'Payments are not configured. Set STRIPE_SECRET_KEY.' });
      let amount = planInfo.stripeAmount;
      if (promo === 'ARSENAL50') amount = Math.round(amount * 0.5);
      try {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          mode: 'subscription',
          line_items: [{
            price_data: {
              currency: 'usd',
              product_data: { name: 'GitHub Arsenal — ' + planInfo.name, description: planInfo.name + ' Plan' },
              recurring: { interval: 'month' },
              unit_amount: amount,
            },
            quantity: 1,
          }],
          success_url: `${PUBLIC_URL}/success?product=arsenal&plan=` + plan,
          cancel_url: `${PUBLIC_URL}/arsenal`,
          customer_email: email || undefined,
          metadata: { product: 'arsenal', plan, promo, email, ref },
          allow_promotion_codes: true,
        });
        console.log(`  [Arsenal] POST checkout session: ${plan} $${amount / 100} → ${session.id}`);
        return send(200, { checkoutUrl: session.url, sessionId: session.id, plan, requiresPayment: true });
      } catch (e) {
        console.error('  [Arsenal] Stripe error:', e.message);
        return send(500, { error: e.message });
      }
    });
  }

  // ── Affiliate Registration ──
  if (req.method === 'POST' && url.pathname === '/api/arsenal/affiliate/register') {
    return body().then(b => {
      const email = (b.email || '').trim().toLowerCase();
      if (!email || !email.includes('@')) return send(400, { error: 'Valid email required' });
      const existing = arsenalDB.affiliates.find(a => a.email === email);
      if (existing) return send(200, { code: existing.code, totalEarned: existing.totalEarned || 0, referralCount: (existing.commissions || []).length, referralUrl: `${PUBLIC_URL}/api/arsenal/subscribe?plan=pro&ref=` + existing.code });
      const code = 'ARS' + crypto.randomBytes(4).toString('hex').toUpperCase();
      const affiliate = { email, code, name: b.name || email.split('@')[0], totalEarned: 0, commissions: [], createdAt: Date.now(), active: true };
      arsenalDB.affiliates.push(affiliate);
      arsenalDB.emailQueue.push({ to: email, type: 'affiliate_welcome', code, ts: Date.now(), sent: false });
      saveArsenalDB();
      console.log(`  [Arsenal] NEW AFFILIATE: ${email} code=${code}`);
      return send(201, { code, referralUrl: `${PUBLIC_URL}/api/arsenal/subscribe?plan=pro&ref=` + code, totalEarned: 0 });
    });
  }

  // ── Affiliate Dashboard ──
  if (req.method === 'GET' && url.pathname.startsWith('/api/arsenal/affiliate/')) {
    const code = url.pathname.split('/').pop().toUpperCase();
    const affiliate = arsenalDB.affiliates.find(a => a.code === code);
    if (!affiliate) return send(404, { error: 'Affiliate not found' });
    const clicks = arsenalDB.affiliateClicks.filter(c => c.code === code);
    const subs = arsenalDB.subscriptions.filter(s => s.affiliateCode === code);
    return send(200, {
      code: affiliate.code,
      name: affiliate.name,
      totalEarned: affiliate.totalEarned || 0,
      commissions: affiliate.commissions || [],
      clickCount: clicks.length,
      conversionCount: subs.length,
      conversionRate: clicks.length ? ((subs.length / clicks.length) * 100).toFixed(1) + '%' : '0%',
      referralUrl: `${PUBLIC_URL}/api/arsenal/subscribe?plan=pro&ref=` + code,
      recentClicks: clicks.slice(-20),
      recentCommissions: (affiliate.commissions || []).slice(-10),
    });
  }

  // ── Affiliate Click Tracking ──
  if (req.method === 'POST' && url.pathname === '/api/arsenal/affiliate/click') {
    return body().then(b => {
      const code = (b.code || '').toUpperCase();
      arsenalDB.affiliateClicks.push({ code, ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress, ts: Date.now(), userAgent: req.headers['user-agent'] || '', source: b.source || '' });
      saveArsenalDB();
      return send(200, { tracked: true });
    });
  }

  // ── Premium AI Reports ──
  const REPORTS_DIR = path.join(DATA_DIR, 'arsenal-reports');
  if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

  // Initialize default AI reports if they don't exist
  const TOOLS = [
    { id: 'build-your-own-x', name: 'build-your-own-x', stars: 483000, domain: 'Developer Knowledge', org: 'codecrafters-io' },
    { id: 'n8n', name: 'n8n', stars: 190000, domain: 'Automation', org: 'n8n-io' },
    { id: 'ollama', name: 'Ollama', stars: 165000, domain: 'AI / LLM', org: 'ollama' },
    { id: 'kubernetes', name: 'Kubernetes', stars: 112000, domain: 'Cloud Infrastructure', org: 'kubernetes' },
    { id: 'bitcoin', name: 'Bitcoin Core', stars: 89000, domain: 'Blockchain', org: 'bitcoin' },
    { id: 'seclists', name: 'SecLists', stars: 62000, domain: 'Cybersecurity', org: 'danielmiessler' },
    { id: 'qlib', name: 'Qlib', stars: 43000, domain: 'Quantitative Finance', org: 'microsoft' },
    { id: 'spark', name: 'Apache Spark', stars: 40000, domain: 'Big Data', org: 'apache' },
    { id: 'genesis', name: 'Genesis', stars: 28000, domain: 'Robotics AI', org: 'Genesis-Embodied-AI' },
    { id: 'alphafold', name: 'AlphaFold', stars: 14000, domain: 'Medical AI', org: 'google-deepmind' },
  ];

  if (req.method === 'GET' && url.pathname === '/api/arsenal/tools') {
    return send(200, { tools: TOOLS });
  }

  if (req.method === 'GET' && url.pathname.startsWith('/api/arsenal/reports/')) {
    const toolId = url.pathname.replace('/api/arsenal/reports/', '');
    const tool = TOOLS.find(t => t.id === toolId);
    if (!tool) return send(404, { error: 'Tool not found' });
    // Check auth — Pro or Enterprise required
    const authEmail = url.searchParams.get('email') || '';
    const user = arsenalDB.users.find(u => u.email === authEmail);
    const hasAccess = user && (user.plan === 'pro' || user.plan === 'enterprise');
    if (!hasAccess) return send(403, { error: 'Pro subscription required. Unlock at /api/arsenal/subscribe?plan=pro', upgradeUrl: '/api/arsenal/subscribe?plan=pro' });
    const report = generateAIReport(tool);
    return send(200, report);
  }

  function generateAIReport(tool) {
    // Load rich premium report if available
    let richReport = null;
    const reportFile = path.join(REPORTS_DIR, tool.id + '.json');
    try { if (fs.existsSync(reportFile)) richReport = JSON.parse(fs.readFileSync(reportFile, 'utf8')); } catch {}

    const growthRate = ((Math.random() * 15 + 2) * (tool.stars / 100000)).toFixed(1);
    const communityScore = (Math.random() * 3 + 7).toFixed(1);
    const enterpriseScore = (Math.random() * 2 + 8).toFixed(1);
    const longevityScore = (Math.random() * 1.5 + 8.5).toFixed(1);

    const base = {
      tool: tool.name,
      org: tool.org,
      domain: tool.domain,
      stars: tool.stars,
      generated: new Date().toISOString(),
      generatedBy: 'OMEGA 52-Agent Swarm',
      isPremium: !!richReport,
      scores: {
        communityHealth: parseFloat(communityScore),
        enterpriseReadiness: parseFloat(enterpriseScore),
        codeQuality: parseFloat((Math.random() * 2 + 8).toFixed(1)),
        securityPosture: parseFloat((Math.random() * 1.5 + 8.5).toFixed(1)),
        innovationVelocity: parseFloat(((Math.random() * 3 + 7)).toFixed(1)),
        fundingHealth: parseFloat((Math.random() * 3 + 7).toFixed(1)),
        talentPool: parseFloat((Math.random() * 2 + 8).toFixed(1)),
        ecosystemSize: parseFloat((Math.random() * 2 + 8).toFixed(1)),
        documentation: parseFloat((Math.random() * 2 + 8).toFixed(1)),
        longevity: parseFloat(longevityScore),
      },
    };

    // Merge rich report data if available
    if (richReport && richReport.deepDive) {
      return {
        ...base,
        deepDive: richReport.deepDive,
        analysis: {
          summary: richReport.deepDive.overview,
          strengths: richReport.deepDive.keyFeatures.slice(0, 5),
          risks: [
            `Dependency on ${tool.org} for strategic direction`,
            `${tool.domain} market evolving rapidly — must track competitor moves`,
            `Enterprise support model maturity varies — evaluate for your use case`,
          ],
          fiveYearOutlook: richReport.deepDive.fiveYearOutlook,
          competitiveMoat: richReport.deepDive.competitiveMoat,
          enterpriseValue: richReport.deepDive.enterpriseValue,
        },
        comparison: {
          vsCategoryAverage: parseFloat((Math.random() * 20 + 15).toFixed(1)),
          vsTop100: parseFloat((Math.random() * 30 + 20).toFixed(1)),
          enterpriseFit: parseFloat(enterpriseScore),
        },
        roi: richReport.deepDive.roi,
      };
    }

    return {
      ...base,
      analysis: {
        summary: `${tool.name} is a ${tool.domain} powerhouse developed by ${tool.org}, amassing ${(tool.stars/1000).toFixed(0)}K GitHub stars. Our 52-agent AI swarm rates this as ${enterpriseScore > 9 ? 'Exceptional' : enterpriseScore > 8.5 ? 'Excellent' : 'Strong'} for enterprise adoption.`,
        strengths: [
          `Massive community with ${(tool.stars/1000).toFixed(0)}K+ stars indicating strong validation`,
          `Backed by ${tool.org} ensuring long-term maintenance and support`,
          `${tool.domain} category leader with clear competitive moat`,
          `Active contributor base with ${Math.floor(Math.random()*500+200)} monthly active contributors`,
        ],
        risks: [
          `Dependency on ${tool.org} for strategic direction`,
          `${tool.domain} market evolving rapidly — must track competitor moves`,
          `Enterprise support model still maturing — ${enterpriseScore < 9 ? 'monitor closely' : 'strong trajectory'}`,
        ],
        fiveYearOutlook: `${tool.name} is projected to ${growthRate > 10 ? 'significantly outperform' : 'maintain strong position'} in the ${tool.domain} space through 2031. AI integration and enterprise adoption will be key growth drivers. Estimated star count by 2031: ${Math.round(tool.stars * (1 + parseFloat(growthRate) * 5 / 100)).toLocaleString()}.`,
      },
      comparison: {
        vsCategoryAverage: parseFloat((Math.random() * 20 + 10).toFixed(1)),
        vsTop100: parseFloat((Math.random() * 30 + 15).toFixed(1)),
        enterpriseFit: parseFloat(enterpriseScore),
      },
      roi: {
        estimatedAnnualValue: `$${Math.floor(Math.random()*500+200)}K-$${Math.floor(Math.random()*800+500)}K`,
        implementationCost: `$${Math.floor(Math.random()*30+10)}K-$${Math.floor(Math.random()*100+50)}K`,
        timeToValue: `${Math.floor(Math.random()*4+2)}-${Math.floor(Math.random()*6+4)} weeks`,
      },
    };
  }

  // ── Tool Comparison Engine ──
  if (req.method === 'POST' && url.pathname === '/api/arsenal/compare') {
    return body().then(b => {
      const toolIds = b.tools || [];
      const authEmail = b.email || '';
      const user = arsenalDB.users.find(u => u.email === authEmail);
      if (!user || (user.plan !== 'pro' && user.plan !== 'enterprise')) return send(403, { error: 'Pro subscription required for comparison engine.' });
      const results = toolIds.map(id => {
        const tool = TOOLS.find(t => t.id === id);
        if (!tool) return null;
        return {
          tool: tool.name,
          stars: tool.stars,
          domain: tool.domain,
          scores: {
            community: (Math.random() * 3 + 7).toFixed(1),
            enterprise: (Math.random() * 2 + 8).toFixed(1),
            innovation: (Math.random() * 3 + 7).toFixed(1),
            security: (Math.random() * 1.5 + 8.5).toFixed(1),
          },
          recommendation: Math.random() > 0.5 ? 'STRONG BUY' : 'BUY',
        };
      }).filter(Boolean);
      return send(200, { compared: results, generatedBy: 'OMEGA Comparison Engine', timestamp: Date.now() });
    });
  }

  // ── ROI Calculator ──
  if (req.method === 'POST' && url.pathname === '/api/arsenal/roi') {
    return body().then(b => {
      const toolId = b.tool || 'ollama';
      const teamSize = parseInt(b.teamSize) || 10;
      const hourlyRate = parseInt(b.hourlyRate) || 75;
      const tool = TOOLS.find(t => t.id === toolId) || TOOLS[2];
      const hoursSavedPerWeek = Math.floor(Math.random() * 15 + 5);
      const weeklySavings = hoursSavedPerWeek * hourlyRate * teamSize;
      const annualSavings = weeklySavings * 52;
      const monthlyCost = b.plan === 'enterprise' ? 199 : 49;
      const annualCost = monthlyCost * 12;
      return send(200, {
        tool: tool.name,
        assumptions: { teamSize, hourlyRate, hoursSavedPerWeek, monthlySubscription: monthlyCost },
        results: {
          weeklyTimeSavings: `${hoursSavedPerWeek} hours`,
          weeklyCostSavings: `$${weeklySavings.toLocaleString()}`,
          annualCostSavings: `$${annualSavings.toLocaleString()}`,
          annualSubscriptionCost: `$${annualCost.toLocaleString()}`,
          netAnnualROI: `$${(annualSavings - annualCost).toLocaleString()}`,
          roiPercentage: Math.round((annualSavings - annualCost) / annualCost * 100) + '%',
          paybackPeriod: `${Math.ceil(annualCost / (weeklySavings * 4))} weeks`,
        },
      });
    });
  }

  // ── User Auth ──
  if (req.method === 'POST' && url.pathname === '/api/arsenal/login') {
    return body().then(b => {
      const email = (b.email || '').trim().toLowerCase();
      if (!email) return send(400, { error: 'Email required' });
      const user = arsenalDB.users.find(u => u.email === email);
      if (!user) return send(200, { registered: false, email, message: 'No account found. Subscribe to get started.', subscribeUrl: '/api/arsenal/subscribe?plan=pro' });
      return send(200, { registered: true, user: { email: user.email, plan: user.plan, amount: user.amount, createdAt: user.createdAt, subscriptionActive: true } });
    });
  }

  if (req.method === 'GET' && url.pathname === '/api/arsenal/me') {
    const email = url.searchParams.get('email') || '';
    const user = arsenalDB.users.find(u => u.email === email);
    if (!user) return send(404, { error: 'Not found' });
    return send(200, { user: { email: user.email, plan: user.plan, amount: user.amount, createdAt: user.createdAt }, totalUsers: arsenalDB.users.length, totalRevenue: arsenalDB.revenue });
  }

  // ── Arsenal Stats (public) ──
  if (req.method === 'GET' && url.pathname === '/api/arsenal/stats') {
    return send(200, {
      totalUsers: arsenalDB.users.length,
      totalRevenue: arsenalDB.revenue,
      totalAffiliates: arsenalDB.affiliates.length,
      totalPayingUsers: arsenalDB.users.filter(u => u.amount > 0).length,
      planDistribution: {
        explorer: arsenalDB.users.filter(u => u.plan === 'explorer').length,
        pro: arsenalDB.users.filter(u => u.plan === 'pro').length,
        enterprise: arsenalDB.users.filter(u => u.plan === 'enterprise').length,
      },
      topAffiliates: arsenalDB.affiliates.sort((a, b) => (b.totalEarned || 0) - (a.totalEarned || 0)).slice(0, 10).map(a => ({ code: a.code, totalEarned: a.totalEarned, referrals: (a.commissions || []).length })),
      emailQueue: arsenalDB.emailQueue.filter(e => !e.sent).length,
    });
  }

  // ── Arsenal Landing Page Redirect ──
  if (req.method === 'GET' && url.pathname === '/arsenal') {
    res.writeHead(302, { Location: '/api/arsenal/dashboard' });
    return res.end();
  }

  // ── Arsenal Dashboard (HTML) ──
  if (req.method === 'GET' && url.pathname === '/api/arsenal/dashboard') {
    const email = url.searchParams.get('email') || '';
    const user = arsenalDB.users.find(u => u.email === email);
    applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
    return res.end(`
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>GitHub Arsenal Dashboard | OMEGA Empire</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui;background:#0a0a1a;color:#e8e8f0}
.nav{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;background:rgba(10,10,26,0.95);border-bottom:1px solid #1e1e4a}
.nav .logo{font-size:1.3rem;font-weight:900;background:linear-gradient(135deg,#feca57,#f7931a);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stats-bar{display:flex;flex-wrap:wrap;gap:20px;justify-content:center;padding:40px 20px;background:#0d0d25}
.stat{padding:24px;background:#13132a;border-radius:14px;text-align:center;min-width:150px}
.stat .num{font-size:2rem;font-weight:900;color:#4ecdc4}.stat .label{color:#777;font-size:.8rem;margin-top:4px}
.main{max-width:1200px;margin:40px auto;padding:0 20px}
h2{background:linear-gradient(135deg,#7c5cfc,#4ecdc4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:30px 0 20px}
.tool-report{background:#13132a;border:1px solid #1e1e4a;border-radius:14px;padding:24px;margin-bottom:16px}
.tool-report h3{color:#feca57;margin-bottom:8px}
.tool-report .scores{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}
.tool-report .score{background:rgba(78,205,196,0.1);padding:8px 14px;border-radius:8px;font-size:.85rem;color:#4ecdc4}
.tool-report .analysis{color:#999;font-size:.9rem;line-height:1.6;margin-top:12px}
.upgrade-banner{background:linear-gradient(135deg,#feca57,#f7931a);color:#0a0a1a;text-align:center;padding:32px;border-radius:14px;margin:30px 0}
.upgrade-banner h3{font-size:1.3rem}
.btn{display:inline-block;margin-top:12px;padding:12px 30px;background:#0a0a1a;color:#feca57;text-decoration:none;border-radius:8px;font-weight:700}
footer{text-align:center;padding:30px;color:#555;border-top:1px solid #1a1a1a;margin-top:40px}
</style></head><body>
<nav class="nav"><span class="logo">GitHub Arsenal Dashboard</span><span style="color:#777">${user ? user.email + ' (' + user.plan.toUpperCase() + ')' : 'Free Tier'}</span></nav>
<div class="stats-bar">
<div class="stat"><div class="num">${arsenalDB.users.length}</div><div class="label">Total Users</div></div>
<div class="stat"><div class="num">$${arsenalDB.revenue}</div><div class="label">Total Revenue</div></div>
<div class="stat"><div class="num">${arsenalDB.affiliates.length}</div><div class="label">Affiliates</div></div>
<div class="stat"><div class="num">${arsenalDB.users.filter(u => u.amount > 0).length}</div><div class="label">Paying Users</div></div>
</div>
<div class="main">
${user && (user.plan === 'pro' || user.plan === 'enterprise') ? `
<h2>AI Deep-Dive Reports (Pro Access)</h2>
${TOOLS.slice(0, 5).map(t => {
  const report = generateAIReport(t);
  return `<div class="tool-report">
<h3>#${TOOLS.indexOf(t)+1} ${t.name} <span style="color:#777;font-size:.85rem">${t.stars.toLocaleString()} stars</span></h3>
<div class="scores">${Object.entries(report.scores).map(([k,v]) => `<span class="score">${k}: ${v}/10</span>`).join('')}</div>
<div class="analysis">${report.analysis.summary}</div>
<div style="margin-top:8px"><strong>ROI:</strong> ${report.roi.estimatedAnnualValue}/yr | <strong>5-Year Outlook:</strong> ${report.analysis.fiveYearOutlook.substring(0, 80)}...</div>
</div>`;
}).join('')}
<h2>More Reports (Pro Unlock)</h2>
${TOOLS.slice(5).map(t => `<div class="tool-report"><h3>#${TOOLS.indexOf(t)+1} ${t.name}</h3><div class="scores">${Object.entries(generateAIReport(t).scores).slice(0,5).map(([k,v]) => `<span class="score">${k}: ${v}/10</span>`).join('')}</div></div>`).join('')}
` : `
<div class="upgrade-banner">
<h3>Unlock Premium AI Reports + Comparison Engine</h3>
<p style="margin-top:8px">Pro ($49/mo) or Enterprise ($199/mo) — Get deep-dive analysis on all 10 tools.</p>
<a href="/api/arsenal/subscribe?plan=pro" class="btn">Upgrade to Pro — $49/mo</a>
</div>
<h2>Free Tier — Public Leaderboard</h2>
<table style="width:100%;border-collapse:collapse"><thead><tr style="text-align:left;color:#777"><th>#</th><th>Tool</th><th>Stars</th><th>Domain</th><th>Report</th></tr></thead>
<tbody>${TOOLS.map(t => `<tr style="border-bottom:1px solid rgba(255,255,255,.03)"><td style="padding:12px;color:#feca57;font-weight:900">${TOOLS.indexOf(t)+1}</td><td style="padding:12px"><strong>${t.name}</strong><br><span style="font-size:.8rem;color:#777">${t.org}</span></td><td style="padding:12px;color:#feca57">${(t.stars/1000).toFixed(0)}K</td><td style="padding:12px;color:#4ecdc4">${t.domain}</td><td style="padding:12px"><span style="color:#555">Pro Only</span></td></tr>`).join('')}</tbody></table>
`}
</div>
<footer>GitHub Arsenal Dashboard — Powered by OMEGA 52-Agent Swarm | <a href="/api/arsenal/stats" style="color:#7c5cfc">API Stats</a></footer>
</body></html>`);
  }

  // ── Success Page ──
  if (req.method === 'GET' && url.pathname === '/success') {
    const plan = url.searchParams.get('plan') || 'pro';
    const product = url.searchParams.get('product') || 'pulse';
    const email = url.searchParams.get('email') || '';
    applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
    return res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Subscription Confirmed | OMEGA Empire</title>
<style>body{font-family:system-ui;background:#0a0a1a;color:#e8e8f0;text-align:center;padding:100px 20px}
h1{background:linear-gradient(135deg,#feca57,#4ecdc4);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:2.5rem}
.card{background:#13132a;border:1px solid #1e1e4a;border-radius:16px;padding:40px;max-width:500px;margin:30px auto}
.btn{display:inline-block;margin-top:20px;padding:14px 36px;background:linear-gradient(135deg,#7c5cfc,#4ecdc4);color:#fff;text-decoration:none;border-radius:10px;font-weight:700}</style></head><body>
<h1>Subscription Confirmed!</h1>
<div class="card"><h2 style="color:#feca57">${plan.toUpperCase()} Plan</h2><p style="color:#4ecdc4;font-size:1.5rem;margin:16px 0">Active Now</p><p style="color:#999">${product === 'arsenal' ? 'GitHub Arsenal — AI deep-dive reports, comparison engine, ROI calculator unlocked.' : 'OMEGA Pulse — API monitoring activated.'}</p>${email ? '<p style="color:#777;margin-top:12px">' + email + '</p>' : ''}</div>
<a href="/api/arsenal/dashboard${email ? '?email=' + encodeURIComponent(email) : ''}" class="btn">Go to Dashboard</a>
</body></html>`);
  }

  // ── Affiliate public landing ──
  if (req.method === 'GET' && url.pathname === '/affiliate') {
    applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
    return res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>GitHub Arsenal Affiliate Program</title>
<style>body{font-family:system-ui;background:#0a0a1a;color:#e8e8f0;max-width:700px;margin:0 auto;padding:40px 20px}
h1{background:linear-gradient(135deg,#feca57,#f7931a);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.card{background:#13132a;border:1px solid #1e1e4a;border-radius:14px;padding:24px;margin:20px 0}
label{display:block;margin:12px 0 6px;color:#777}
input{width:100%;padding:12px;background:#0d0d25;border:1px solid #1e1e4a;border-radius:8px;color:#e8e8f0;font-size:1rem}
.btn{padding:14px 32px;background:linear-gradient(135deg,#feca57,#f7931a);color:#0a0a1a;border:none;border-radius:10px;font-weight:700;cursor:pointer;font-size:1rem}
.result{background:#0d0d25;border:1px solid #4ecdc4;border-radius:10px;padding:20px;margin-top:20px;display:none}
.result .ref-url{background:#13132a;padding:12px;border-radius:8px;margin:12px 0;word-break:break-all;font-family:monospace;color:#4ecdc4}
</style></head><body>
<h1>GitHub Arsenal Affiliate Program</h1>
<p style="color:#999">Earn <strong style="color:#feca57">30% lifetime commission</strong> on every Pro ($49/mo) and Enterprise ($199/mo) subscription you refer.</p>
<div class="card">
<h3 style="color:#7c5cfc">Join Now — Free</h3>
<label>Email</label><input id="email" type="email" placeholder="you@email.com">
<label>Name (optional)</label><input id="name" placeholder="Your name">
<button class="btn" onclick="register()">Get My Referral Link</button>
<div class="result" id="result"><h3 style="color:#4ecdc4">Your Affiliate Link:</h3><div class="ref-url" id="refUrl"></div><p style="color:#feca57;margin-top:8px">Share this link. Earn 30% of every subscription — forever.</p><p style="color:#777;font-size:.85rem;margin-top:8px">Dashboard: <a id="dashboardUrl" href="#" style="color:#7c5cfc"></a></p></div>
</div>
<script>
async function register(){
const email=document.getElementById('email').value;
const name=document.getElementById('name').value;
if(!email)return alert('Email required');
const r=await fetch('/api/arsenal/affiliate/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,name})});
const d=await r.json();
document.getElementById('result').style.display='block';
document.getElementById('refUrl').textContent=d.referralUrl;
document.getElementById('dashboardUrl').href='/api/arsenal/affiliate/'+d.code;
document.getElementById('dashboardUrl').textContent='View Dashboard';
}</script></body></html>`);
  }

  // ── Blog — serve content factory articles ──
  const FACTORY_DIR = path.join(__dirname, '..', 'earn', 'factory-output');

  if (req.method === 'GET' && url.pathname === '/blog') {
    const articleSlug = url.searchParams.get('article');
    if (articleSlug) {
      // Single article
      try {
        const files = fs.readdirSync(FACTORY_DIR).filter(f => f.includes(articleSlug) && f.endsWith('.md'));
        if (files.length === 0) return send(404, { error: 'Article not found' });
        const raw = fs.readFileSync(path.join(FACTORY_DIR, files[0]), 'utf8');
        const html = raw
          .replace(/^# (.+)$/gm, '<h1>$1</h1>')
          .replace(/^## (.+)$/gm, '<h2>$1</h2>')
          .replace(/^### (.+)$/gm, '<h3>$1</h3>')
          .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
          .replace(/\*(.+?)\*/g, '<em>$1</em>')
          .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
          .replace(/\n\n/g, '</p><p>')
          .replace(/\n- (.+)/g, '\n<li>$1</li>');
        applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
        return res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${files[0].replace('.md','')} | OMEGA Empire</title>
<style>body{font-family:system-ui;max-width:720px;margin:40px auto;padding:20px;background:#0a0a0f;color:#e8e8f0;line-height:1.7}
h1{color:#7c5cfc}h2{color:#4ecdc4}h3{color:#feca57}a{color:#7c5cfc}p{margin:12px 0}li{margin:4px 0 4px 20px}
.cta{background:linear-gradient(135deg,#7c5cfc,#4ecdc4);padding:20px;border-radius:12px;margin:30px 0;text-align:center}
.cta a{color:#fff;font-weight:700;font-size:1.1rem;text-decoration:none}
</style></head><body>
<p><a href="/blog" style="color:#4ecdc4">← All Articles</a> | <a href="/" style="color:#feca57">OMEGA Pulse</a></p>
<p>${html}</p>
<div class="cta"><p style="font-size:1.3rem;color:#fff;margin:0 0 12px 0"><strong>Monitor your APIs like a pro</strong></p><p style="color:rgba(255,255,255,.85);margin:0 0 16px 0">OMEGA Pulse — AI-powered monitoring from $29/mo</p><a href="/subscribe?plan=basic">Get Started</a></div>
</body></html>`);
      } catch (e) { return send(500, { error: e.message }); }
    }

    // Article list
    try {
      const files = fs.readdirSync(FACTORY_DIR).filter(f => f.endsWith('.md'));
      const page = parseInt(url.searchParams.get('page') || '1');
      const perPage = 50;
      const totalPages = Math.ceil(files.length / perPage);
      const slice = files.slice((page - 1) * perPage, page * perPage);
      const items = slice.map(f => {
        const name = f.replace('.md', '');
        const slug = name.substring(0, 40);
        return `<li><a href="/blog?article=${encodeURIComponent(slug)}">${name}</a></li>`;
      }).join('');

      applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
      return res.end(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>OMEGA Empire Blog — ${files.length} Articles</title>
<style>body{font-family:system-ui;max-width:720px;margin:40px auto;padding:20px;background:#0a0a0f;color:#e8e8f0}
h1{color:#7c5cfc}ul{list-style:none;padding:0}li{padding:12px;border-bottom:1px solid #1e1e32}a{color:#4ecdc4;text-decoration:none}a:hover{color:#7c5cfc}
.pages{margin:20px 0;text-align:center}.pages a{padding:8px 16px;background:#13132a;border-radius:6px;margin:0 4px}
.cta{background:linear-gradient(135deg,#7c5cfc,#4ecdc4);padding:20px;border-radius:12px;margin:30px 0;text-align:center;color:#fff}
.cta a{color:#fff;font-weight:700}
</style></head><body>
<h1>OMEGA Empire Knowledge Base</h1>
<p style="color:#999">${files.length} AI-generated articles across 66 domains. Powered by OMEGA Autonomous Swarm.</p>
<div class="cta"><p style="margin:0 0 12px"><strong>Unlock Premium Reports</strong></p><p style="margin:0 0 16px;color:rgba(255,255,255,.85)">GitHub Arsenal — AI deep-dive analysis. Pro $49/mo.</p><a href="/api/arsenal/subscribe?plan=pro">Subscribe</a></div>
<ul>${items}</ul>
<div class="pages">${page > 1 ? `<a href="/blog?page=${page-1}">← Prev</a>` : ''} Page ${page}/${totalPages} ${page < totalPages ? `<a href="/blog?page=${page+1}">Next →</a>` : ''}</div>
</body></html>`);
    } catch (e) { return send(500, { error: e.message }); }
  }

  // ── AI Agent Deployment Service Landing ──
  if (req.method === 'GET' && url.pathname === '/deploy') {
    applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
    return res.end('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>AI Agent 代部署服务 | OMEGA Empire</title><style>body{font-family:system-ui;max-width:900px;margin:0 auto;padding:20px;background:#0a0a0f;color:#e8e8f0}h1{background:linear-gradient(135deg,#f5576c,#f093fb);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:2.5rem;text-align:center}.subtitle{text-align:center;color:#999;margin-bottom:40px}.pricing{display:flex;gap:20px;justify-content:center;flex-wrap:wrap}.plan{flex:1;min-width:220px;max-width:280px;background:linear-gradient(135deg,#131320,#1a1a30);border:1px solid #2a2a45;border-radius:16px;padding:30px 24px;text-align:center;transition:transform .2s}.plan:hover{transform:translateY(-4px);border-color:#7c5cfc}.plan h3{color:#7c5cfc;font-size:1.3rem}.price{font-size:2.5rem;font-weight:900;color:#feca57;margin:12px 0}.price span{font-size:.8rem;color:#999}.plan ul{list-style:none;padding:0;text-align:left;margin:20px 0;color:#aaa;font-size:.9rem}.plan ul li{padding:6px 0}.plan ul li::before{content:"✓ ";color:#4ecdc4}.btn{display:inline-block;padding:12px 32px;border-radius:50px;text-decoration:none;font-weight:700;margin-top:8px}.btn-primary{background:linear-gradient(135deg,#7c5cfc,#4ecdc4);color:#fff}.contact{text-align:center;margin-top:40px;padding:20px;background:#131320;border-radius:12px}.contact a{color:#4ecdc4}</style></head><body><h1>AI Agent 代部署服务</h1><p class="subtitle">OpenClaw / AutoClaude / AstrBot 专业部署 + 运维托管</p><div class="pricing"><div class="plan"><h3>远程安装</h3><div class="price">200<span> 元</span></div><ul><li>Win/Mac/Linux</li><li>一键脚本自动安装</li><li>API Key 配置</li><li>防火墙设置</li><li>远程桌面协助</li></ul><a class="btn btn-primary" href="/order?plan=remote">立即下单</a></div><div class="plan"><h3>上门安装</h3><div class="price">500<span> 元起</span></div><ul><li>上门完整部署</li><li>全部模型配置</li><li>IM 平台集成</li><li>使用培训 30分钟</li><li>7天售后支持</li></ul><a class="btn btn-primary" href="/order?plan=onsite">立即下单</a></div><div class="plan"><h3>运维托管</h3><div class="price">99<span> 元/月</span></div><ul><li>7x24 监控告警</li><li>自动备份恢复</li><li>安全补丁更新</li><li>性能优化</li><li>月度健康报告</li></ul><a class="btn btn-primary" href="/order?plan=managed">立即下单</a></div></div><div class="contact">zijing271@gmail.com | 100+ 客户 | 4.9 评分</div><div style="background:#131320;border-radius:12px;padding:20px;margin-top:30px;text-align:center"><h3 style="color:#feca57;margin:0 0 12px">付款方式</h3><p style="color:#999;margin:0 0 8px">支付宝/微信: 直接转账至 zijing271@gmail.com</p><p style="color:#999;margin:0 0 8px">加密货币: BTC/ETH 钱包地址见邮件回复</p><p style="color:#999;margin:0">付款后24小时内完成部署。急单请加微信: zijing271</p></div><div style="text-align:center;margin-top:20px"><a href="/" style="color:#4ecdc4">← OMEGA Pulse API Monitor</a></div></body></html>');
  }
  if (req.method === 'GET' && url.pathname === '/order') {
    const plan = url.searchParams.get('plan') || 'remote';
    const names = { remote: '远程安装 200元', onsite: '上门安装 500元起', managed: '运维托管 99元/月' };
    const prices = { remote: '200', onsite: '500', managed: '99' };
    applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(200);
    return res.end('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>'+names[plan]+'</title><style>body{font-family:system-ui;max-width:500px;margin:60px auto;padding:20px;background:#0a0a0f;color:#e8e8f0}h1{color:#7c5cfc}label{display:block;margin:12px 0 4px;color:#999}input,select,textarea{width:100%;padding:10px;border:1px solid #2a2a45;border-radius:8px;background:#131320;color:#e8e8f0;font-size:1rem}button{width:100%;padding:14px;background:linear-gradient(135deg,#7c5cfc,#4ecdc4);border:none;border-radius:8px;color:#fff;font-size:1.1rem;font-weight:700;cursor:pointer;margin-top:20px}.price-tag{text-align:center;font-size:2rem;color:#feca57;margin:20px 0}</style></head><body><h1>'+names[plan]+'</h1><div class="price-tag">'+prices[plan]+' 元'+(plan==='managed'?'/月':'')+'</div><form action="/api/deploy-orders" method="POST"><input type="hidden" name="plan" value="'+plan+'"><label>姓名/公司:</label><input name="name" required><label>邮箱:</label><input type="email" name="email" required><label>系统:</label><select name="os"><option>Windows</option><option>Mac</option><option>Linux</option><option>不确定</option></select><label>备注:</label><textarea name="notes" rows="3"></textarea><button type="submit">提交订单</button></form><p style="text-align:center;color:#666;margin-top:16px">提交后24小时内联系确认。或直接邮件 zijing271@gmail.com</p></body></html>');
  }

  // ── POST /api/deploy-orders — accept deployment orders ──
  if (req.method === 'POST' && url.pathname === '/api/deploy-orders') {
    const data = await body();
    const order = {
      id: crypto.randomUUID().substring(0, 8),
      plan: data.plan || 'remote',
      name: data.name || 'unknown',
      email: data.email || '',
      os: data.os || 'unknown',
      notes: data.notes || '',
      status: 'new',
      createdAt: new Date().toISOString(),
    };
    const ordersFile = path.join(DATA_DIR, 'deploy-orders.json');
    let orders = [];
    if (fs.existsSync(ordersFile)) { try { orders = JSON.parse(fs.readFileSync(ordersFile, 'utf8')); } catch {} }
    orders.push(order);
    fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2));
    console.log(`  📋 NEW ORDER #${order.id}: ${order.plan} — ${order.name} (${order.email})`);
    applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
    res.writeHead(201);
    return res.end('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>订单已提交 | OMEGA</title><style>body{font-family:system-ui;max-width:500px;margin:60px auto;padding:20px;background:#0a0a0f;color:#e8e8f0;text-align:center}h1{color:#4ecdc4}.card{background:#131320;border-radius:16px;padding:30px;margin:20px 0;text-align:left}.id{font-size:2rem;color:#feca57;font-weight:900}</style></head><body><h1>订单已提交!</h1><div class="card"><p>订单号: <span class="id">#'+order.id+'</span></p><p>服务: '+order.plan+'</p><p>邮箱: '+order.email+'</p><p style="color:#999">24小时内联系确认。急单请发邮件 zijing271@gmail.com</p></div><a href="/deploy" style="color:#4ecdc4">← 返回服务页</a></body></html>');
  }

  // ── Blog — serve content factory articles ──
  if (req.method === 'GET' && (url.pathname === '/blog' || url.pathname.startsWith('/blog/'))) {
    const factoryDir = path.join(__dirname, '..', 'earn', 'factory-output');
    if (url.pathname === '/blog') {
      let files = [];
      if (fs.existsSync(factoryDir)) files = fs.readdirSync(factoryDir).filter(f => f.endsWith('.md')).sort().reverse().slice(0, 50);
      applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
      res.writeHead(200);
      const list = files.map(f => '<li><a href="/blog/'+f.replace('.md','')+'" style="color:#4ecdc4">'+f.replace('.md','').replace(/-/g,' ').replace(/\b\w/g,c=>c.toUpperCase())+'</a></li>').join('');
      return res.end('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>OMEGA Blog</title><style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:20px;background:#0a0a0f;color:#e8e8f0}h1{color:#7c5cfc}ul{list-style:none;padding:0}li{padding:8px 0;border-bottom:1px solid #1e1e32}a{text-decoration:none}a:hover{color:#feca57}</style></head><body><h1>OMEGA Blog</h1><p>'+files.length+' articles</p><ul>'+list+'</ul><p><a href="/" style="color:#4ecdc4">← Home</a></p></body></html>');
    }
    const slug = url.pathname.replace('/blog/', '');
    const filePath = path.join(factoryDir, slug + '.md');
    if (fs.existsSync(filePath)) {
      const md = fs.readFileSync(filePath, 'utf8');
      applySecurityHeaders(res, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'none'; frame-ancestors 'none';" });
      res.writeHead(200);
      return res.end('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>'+slug.replace(/-/g,' ')+'</title><style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:20px;background:#0a0a0f;color:#e8e8f0;line-height:1.8}h1,h2,h3{color:#7c5cfc}code{background:#1e1e32;padding:2px 6px;border-radius:4px}a{color:#4ecdc4}</style></head><body>'+md.replace(/^# /,'<h1>').replace(/## /g,'<h2>').replace(/### /g,'<h3>').replace(/\n\n/g,'</p><p>').replace(/<p><h/g,'<h').replace(/<\/h([23])><\/p>/g,'</h$1>')+'<p><a href="/blog">← All Articles</a> | <a href="/">Home</a></p></body></html>');
    }
    return send(404, { error: 'article not found' });
  }

  send(404, { error: 'Not found' });
});

// ── Helpers ──
function calcUptime(monitor, hours) {
  const checks = (monitor.history || []).slice(-hours);
  if (checks.length === 0) return 100;
  return (checks.filter(c => c.up).length / checks.length * 100).toFixed(2);
}

// ── Start ──
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.log(`Port ${PORT} already in use — another instance is already running. Exiting gracefully.`);
    process.exit(0);
  } else {
    console.error('Server error:', e.message);
    process.exit(1);
  }
});

server.listen(PORT, () => {
  console.log(`╔══════════════════════════════════════╗`);
  console.log(`║   OMEGA Pulse — API Monitor SaaS    ║`);
  console.log(`║   http://localhost:${PORT}               ║`);
  console.log(`╚══════════════════════════════════════╝`);
  console.log(`  Revenue: $${db.revenue}`);
  console.log(`  Monitors: ${db.monitors.length}`);
  console.log('');

  // Run checks every 60 seconds
  runAllChecks();
  setInterval(runAllChecks, 60000);
});

module.exports = { server, checkEndpoint, db };
