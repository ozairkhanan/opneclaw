require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const https = require('https');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3747;
const JWT_SECRET = process.env.JWT_SECRET || 'openclaw_secret_key_2026';

app.use(cors());
app.use(express.json());

// ── MongoDB Models ──────────────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// ── Connect to MongoDB ──────────────────────────────────────────────────────

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('MongoDB connection error:', err));

// ── Middleware ──────────────────────────────────────────────────────────────

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
};

// ── Auth Routes ─────────────────────────────────────────────────────────────

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: user.email });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── API Proxy Helpers ───────────────────────────────────────────────────────

function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function mintegralToken(apiKey) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const innerMd5 = crypto.createHash('md5').update(ts).digest('hex');
  const token = crypto.createHash('md5').update(apiKey + innerMd5).digest('hex');
  return { token, ts };
}

function formatDate(offsetDays) {
  const d = new Date();
  d.setDate(d.getDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

// ── Proxy Routes ────────────────────────────────────────────────────────────

// Mintegral Report
app.get('/mintegral/report', authenticate, async (req, res) => {
  const mintSkey = process.env.MINT_SKEY;
  const mintAccessKey = process.env.MINT_ACCESS_KEY;

  if (!mintSkey || !mintAccessKey) {
    return res.status(400).json({ error: 'Mintegral credentials not configured in server .env' });
  }

  const { startDate, endDate, groupBy = 'date,app_id' } = req.query;
  const { token, ts } = mintegralToken(mintSkey);

  const params = new URLSearchParams({
    start_date: startDate || formatDate(-7),
    end_date:   endDate   || formatDate(-1),
    per_page:   '200',
    page:       '1',
    group_by:   groupBy,
  });

  const options = {
    hostname: 'ss-api.mintegral.com',
    path: `/api/v1/reports/data?${params.toString()}`,
    method: 'GET',
    headers: { 'access-key': mintAccessKey, 'token': token, 'timestamp': ts, 'Content-Type': 'application/json' },
  };

  try {
    const result = await httpsRequest(options);
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// AdMob Proxy Routes
app.post('/admob/report', authenticate, async (req, res) => {
  const pubId = process.env.ADMOB_PUBLISHER_ID;
  const { accessToken, startDate, endDate } = req.body;

  if (!accessToken || !pubId) {
    return res.status(400).json({ error: 'accessToken required, and ADMOB_PUBLISHER_ID must be set in server .env' });
  }

  const [sy, sm, sd] = (startDate || formatDate(-7)).split('-').map(Number);
  const [ey, em, ed] = (endDate   || formatDate(-1)).split('-').map(Number);
  const dateRange = { startDate: { year: sy, month: sm, day: sd }, endDate: { year: ey, month: em, day: ed } };

  const mediationBody = JSON.stringify({
    reportSpec: {
      dateRange,
      dimensions: ['DATE', 'APP', 'AD_SOURCE'],
      metrics: ['ESTIMATED_EARNINGS', 'IMPRESSIONS', 'CLICKS', 'AD_REQUESTS', 'MATCHED_REQUESTS', 'OBSERVED_ECPM', 'MATCH_RATE'],
      sortConditions: [{ dimension: 'DATE', order: 'DESCENDING' }],
    },
  });

  const makeOptions = (path) => ({
    hostname: 'admob.googleapis.com',
    path,
    method: 'POST',
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
  });

  try {
    const result = await httpsRequest(makeOptions(`/v1/accounts/${pubId}/mediationReport:generate`), mediationBody);
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// AdMob Auth URL
app.get('/admob/auth-url', authenticate, async (req, res) => {
  const clientId = process.env.ADMOB_CLIENT_ID;
  if (!clientId) return res.status(400).json({ error: 'ADMOB_CLIENT_ID missing in server .env' });

  const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id:     clientId,
    redirect_uri:  'urn:ietf:wg:oauth:2.0:oob',
    response_type: 'code',
    scope:         'https://www.googleapis.com/auth/admob.readonly https://www.googleapis.com/auth/admob.report',
    access_type:   'offline',
    prompt:        'consent',
  }).toString();

  res.json({ authUrl });
});

// AdMob Token Exchange
app.post('/admob/token-exchange', authenticate, async (req, res) => {
  const { code } = req.body;
  const clientId = process.env.ADMOB_CLIENT_ID;
  const clientSecret = process.env.ADMOB_CLIENT_SECRET;

  if (!clientId || !clientSecret) return res.status(400).json({ error: 'AdMob credentials missing in server .env' });

  const params = new URLSearchParams({
    code,
    client_id:     clientId,
    client_secret: clientSecret,
    redirect_uri:  'urn:ietf:wg:oauth:2.0:oob',
    grant_type:    'authorization_code',
  }).toString();

  const options = {
    hostname: 'oauth2.googleapis.com',
    path: '/token',
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(params) },
  };

  try {
    const result = await httpsRequest(options, params);
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// AdMob Token Refresh
app.post('/admob/token-refresh', authenticate, async (req, res) => {
  const { refreshToken } = req.body;
  const clientId = process.env.ADMOB_CLIENT_ID;
  const clientSecret = process.env.ADMOB_CLIENT_SECRET;

  if (!clientId || !clientSecret) return res.status(400).json({ error: 'AdMob credentials missing in server .env' });

  const params = new URLSearchParams({
    client_id:     clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken,
    grant_type:    'refresh_token',
  }).toString();

  const options = {
    hostname: 'oauth2.googleapis.com',
    path: '/token',
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(params) },
  };

  try {
    const result = await httpsRequest(options, params);
    res.status(result.status).json(result.body);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🦞 OpenClaw Backend running at http://localhost:${PORT}`);
});
