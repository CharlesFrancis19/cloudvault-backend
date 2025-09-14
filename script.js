// server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';

import { S3Client, ListObjectsV2Command, HeadBucketCommand, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

/** ====== ENV / DEFAULTS ====== */
const PORT = process.env.PORT || 8000;

// Auth / DDB
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const DDB_TABLE = process.env.DDB_TABLE || 'Users'; // PK (S), SK (S)
const USER_SK = process.env.USER_SK || 'USER';

// S3 (your values)
const ACCOUNT_ID = process.env.AWS_ACCOUNT_ID || '342448511865';
const BUCKET_NAME = process.env.S3_BUCKET || 'secure-buckett';
const S3_REGION = process.env.S3_REGION || 'us-east-1';

// CORS for dev
const CORS_ORIGINS =
  (process.env.CORS_ORIGINS &&
    process.env.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)) ||
  ['http://localhost:3000', 'http://192.168.56.1:3000','https://d1e7o1ng62c5j.cloudfront.net'];

/** ====== AWS CLIENTS ====== */
const ddbClient = new DynamoDBClient({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(ddbClient, {
  marshallOptions: { convertEmptyValues: true, removeUndefinedValues: true, convertClassInstanceToMap: true },
});
const s3 = new S3Client({ region: S3_REGION });

/** ====== APP ====== */
const app = express();
const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked for origin: ${origin}`), false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

/** ====== HELPERS ====== */
const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
const nowIso = () => new Date().toISOString();
const sanitize = (name) => name.replace(/[^\w.\- ]+/g, '_');

function authRequired(req, res, next) {
  const hdr = req.headers['authorization'];
  if (!hdr?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing bearer token' });
  try {
    req.user = jwt.verify(hdr.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
const userPrefix = (req) => `users/${(req.user?.email || 'anon').toLowerCase()}/`;

/** ====== HEALTH ====== */
app.get('/health', async (_req, res) => {
  try {
    await s3.send(new HeadBucketCommand({ Bucket: BUCKET_NAME }));
    res.json({ ok: true, bucket: BUCKET_NAME });
  } catch (e) {
    res.json({ ok: false, error: String(e?.message || e) });
  }
});

/** ====== AUTH (DynamoDB) ====== */
app.post('/signup', async (req, res) => {
  try {
    const name = (req.body?.name || '').trim();
    const email = (req.body?.email || '').toLowerCase().trim();
    const password = req.body?.password || '';
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing name/email/password' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const passwordHash = await bcrypt.hash(password, 10);
    await ddb.send(new PutCommand({
      TableName: DDB_TABLE,
      Item: { PK: email, SK: USER_SK, email, name, passwordHash, createdAt: nowIso() },
      ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
    }));

    const token = signToken({ sub: email, email, src: 'dynamo' });
    res.json({ message: 'Signup success', accessToken: token, user: { email, name } });
  } catch (err) {
    if (err?.name === 'ConditionalCheckFailedException') return res.status(409).json({ error: 'User already exists' });
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Failed to sign up' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase().trim();
    const password = req.body?.password || '';
    if (!email || !password) return res.status(400).json({ error: 'Missing email/password' });

    const out = await ddb.send(new GetCommand({ TableName: DDB_TABLE, Key: { PK: email, SK: USER_SK } }));
    if (!out.Item) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(password, out.Item.passwordHash || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ sub: email, email, src: 'dynamo' });
    res.json({ message: 'Login success', accessToken: token, user: { email, name: out.Item.name || '' } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to login' });
  }
});

/** ====== S3: presign & list ====== */

// presigned PUT (upload) — includes SSE AES256 to match your CLI
app.post('/api/files/presign/upload', authRequired, async (req, res) => {
  try {
    const { fileName, contentType } = req.body || {};
    if (!fileName) return res.status(400).json({ error: 'Missing fileName' });

    const safeName = sanitize(fileName);
    const key = `${userPrefix(req)}${Date.now()}_${safeName}`;

    const cmd = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      ContentType: contentType || 'application/octet-stream',
      ServerSideEncryption: 'AES256', // <- important
    });

    const uploadUrl = await getSignedUrl(s3, cmd, { expiresIn: 60 * 5 });
    res.json({ uploadUrl, key });
  } catch (err) {
    console.error('Presign upload error:', err);
    res.status(500).json({ error: 'Failed to create upload URL' });
  }
});

// list objects for current user
app.get('/api/files/list', authRequired, async (req, res) => {
  try {
    const Prefix = userPrefix(req);
    const out = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET_NAME, Prefix, MaxKeys: 100 }));
    const items = (out.Contents || []).map(o => ({ key: o.Key, size: o.Size, lastModified: o.LastModified }));
    res.json({ items });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

// presigned GET for inline view
app.get('/api/files/presign/view', authRequired, async (req, res) => {
  try {
    const key = String(req.query.key || '');
    if (!key) return res.status(400).json({ error: 'Missing key' });
    if (!key.startsWith(userPrefix(req))) return res.status(403).json({ error: 'Forbidden key' });

    const cmd = new GetObjectCommand({ Bucket: BUCKET_NAME, Key: key, ResponseContentDisposition: 'inline' });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 60 * 5 });
    res.json({ url });
  } catch (err) {
    console.error('Presign view error:', err);
    res.status(500).json({ error: 'Failed to create view URL' });
  }
});

// presigned GET for download
app.get('/api/files/presign/download', authRequired, async (req, res) => {
  try {
    const key = String(req.query.key || '');
    if (!key) return res.status(400).json({ error: 'Missing key' });
    if (!key.startsWith(userPrefix(req))) return res.status(403).json({ error: 'Forbidden key' });

    const cmd = new GetObjectCommand({ Bucket: BUCKET_NAME, Key: key, ResponseContentDisposition: 'attachment' });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 60 * 5 });
    res.json({ url });
  } catch (err) {
    console.error('Presign download error:', err);
    res.status(500).json({ error: 'Failed to create download URL' });
  }
});

/** ====== START ====== */
app.listen(PORT, () => {
  console.log(`✅ API http://localhost:${PORT}`);
  console.log(`🪣 S3: s3://${BUCKET_NAME} (${S3_REGION}) acct ${ACCOUNT_ID}`);
  console.log(`🔓 CORS: ${CORS_ORIGINS.join(', ')}`);
});
