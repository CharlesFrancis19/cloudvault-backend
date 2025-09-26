// server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';

import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  ResendConfirmationCodeCommand,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  AssociateSoftwareTokenCommand,
  VerifySoftwareTokenCommand,
} from '@aws-sdk/client-cognito-identity-provider';

import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';

import {
  S3Client,
  ListObjectsV2Command,
  HeadBucketCommand,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

/* ========= ENV ========= */
const PORT = Number(process.env.PORT) || 8080;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_REGION = process.env.S3_REGION || AWS_REGION;
const BUCKET_NAME = process.env.S3_BUCKET || 'missing-bucket';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';
const CLIENT_ID = process.env.COGNITO_CLIENT_ID || '';
const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN || '';
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL || '';

/* ========= CORS ========= */
const RAW_ORIGINS = (process.env.CORS_ORIGINS && process.env.CORS_ORIGINS.split(',')) || [
  'http://localhost:3000',
  'https://d1e7o1ng62c5j.cloudfront.net',
];
const ALLOW_SET = new Set(
  RAW_ORIGINS.map(s => (s || '').trim()).filter(Boolean).map(o => o.replace(/\/+$/, '').toLowerCase())
);

/* ========= AWS CLIENTS ========= */
const cognito = new CognitoIdentityProviderClient({ region: AWS_REGION });
const s3 = new S3Client({ region: S3_REGION });
const sns = SNS_TOPIC_ARN ? new SNSClient({ region: AWS_REGION }) : null;
const sqs = SQS_QUEUE_URL ? new SQSClient({ region: AWS_REGION }) : null;

/* ========= APP ========= */
const app = express();
app.use(express.json());

const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    const norm = origin.replace(/\/+$/, '').toLowerCase();
    if (ALLOW_SET.has(norm)) return cb(null, true);
    return cb(new Error(`CORS blocked for origin: ${origin}`), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

/* ========= HELPERS ========= */
const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
const sanitize = (name) => String(name || '').replace(/[^\w.\- ]+/g, '_');

function authRequired(req, res, next) {
  const hdr = req.headers['authorization'];
  if (!hdr?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing bearer token' });
  try {
    req.user = jwt.verify(hdr.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
const userPrefix = (req) => `users/${(req.user?.email || 'anon').toLowerCase()}/`;

async function publishSNS(subject, message) {
  if (!sns || !SNS_TOPIC_ARN) return;
  try {
    await sns.send(new PublishCommand({ TopicArn: SNS_TOPIC_ARN, Subject: subject, Message: message }));
  } catch (e) {
    console.error('SNS publish failed:', e);
  }
}

async function sendSQS(eventType, payload) {
  if (!sqs || !SQS_QUEUE_URL) return;
  try {
    await sqs.send(new SendMessageCommand({
      QueueUrl: SQS_QUEUE_URL,
      MessageBody: JSON.stringify({ eventType, ...payload, ts: new Date().toISOString() }),
      MessageAttributes: {
        eventType: { DataType: 'String', StringValue: eventType },
        ...(payload?.email ? { email: { DataType: 'String', StringValue: payload.email } } : {}),
      },
    }));
  } catch (e) {
    console.error('SQS send failed:', e);
  }
}

/* ========= HEALTH ========= */
app.get('/health', async (_req, res) => {
  try {
    const s3Ok = await s3.send(new HeadBucketCommand({ Bucket: BUCKET_NAME })).then(() => true).catch(() => false);
    res.json({
      ok: true,
      bucket: BUCKET_NAME,
      s3Ok,
      cognitoConfigured: !!(USER_POOL_ID && CLIENT_ID),
      snsConfigured: !!SNS_TOPIC_ARN,
      sqsConfigured: !!SQS_QUEUE_URL,
    });
  } catch (e) {
    res.json({ ok: false, error: String(e?.message || e) });
  }
});

/* ========= AUTH (Cognito) ========= */

app.post('/signup', async (req, res) => {
  try {
    const name = (req.body?.name || '').trim();
    const email = (req.body?.email || '').toLowerCase().trim();
    const password = req.body?.password || '';
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing name/email/password' });

    await cognito.send(new SignUpCommand({
      ClientId: CLIENT_ID,
      Username: email,
      Password: password,
      UserAttributes: [{ Name: 'email', Value: email }, { Name: 'name', Value: name }],
    }));

    await publishSNS('Signup initiated', `New signup for ${email}`);
    res.json({ message: 'Signup initiated. Check your email for a confirmation code.', requiresConfirmation: true });
  } catch (err) {
    console.error('SignUp error:', err);
    if (err?.name === 'InvalidPasswordException') {
      return res.status(400).json({ error: 'Password does not meet policy (needs upper, lower, number, symbol).' });
    }
    if (err?.name === 'UsernameExistsException') {
      return res.status(409).json({ error: 'User already exists' });
    }
    res.status(500).json({ error: 'Failed to sign up' });
  }
});

app.post('/resend-confirmation', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ error: 'Missing email' });

    await cognito.send(new ResendConfirmationCodeCommand({
      ClientId: CLIENT_ID,
      Username: email,
    }));
    res.json({ message: 'Confirmation code resent' });
  } catch (err) {
    console.error('Resend confirmation error:', err);
    res.status(500).json({ error: 'Failed to resend confirmation code' });
  }
});

app.post('/confirm-signup', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase().trim();
    const code = (req.body?.code || '').trim();
    const password = (req.body?.password || '').trim();
    if (!email || !code || !password) return res.status(400).json({ error: 'Missing email/code/password' });

    await cognito.send(new ConfirmSignUpCommand({
      ClientId: CLIENT_ID,
      Username: email,
      ConfirmationCode: code,
    }));

    await publishSNS('Email confirmed', `Email confirmed for ${email}`);

    const init = await cognito.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password },
    }));

    if (init.ChallengeName === 'MFA_SETUP') {
      return res.json({ challengeName: 'MFA_SETUP', session: init.Session, message: 'MFA setup required' });
    }
    if (init.ChallengeName) {
      return res.json({ challengeName: init.ChallengeName, session: init.Session, message: 'Challenge returned' });
    }
    return res.json({ message: 'Confirmed. Please sign in.' });
  } catch (err) {
    console.error('ConfirmSignUp error:', err);
    res.status(500).json({ error: 'Failed to confirm signup' });
  }
});

app.post('/mfa/setup/start', async (req, res) => {
  try {
    const session = req.body?.session;
    const email = (req.body?.email || '').toLowerCase().trim();
    if (!session) return res.status(400).json({ error: 'Missing session' });

    const out = await cognito.send(new AssociateSoftwareTokenCommand({ Session: session }));
    const secretCode = out?.SecretCode;
    const uriLabel = encodeURIComponent(`SecureVault:${email || 'user'}`);
    const issuer = encodeURIComponent('SecureVault');
    const otpauth = `otpauth://totp/${uriLabel}?secret=${secretCode}&issuer=${issuer}`;

    res.json({ secretCode, otpauth, session: out.Session || session });
  } catch (err) {
    console.error('MFA setup start error:', err);
    res.status(500).json({ error: 'Failed to start MFA setup' });
  }
});

app.post('/mfa/setup/verify', async (req, res) => {
  try {
    const { email, code, session } = req.body || {};
    if (!email || !code || !session) return res.status(400).json({ error: 'Missing email/code/session' });

    const verify = await cognito.send(new VerifySoftwareTokenCommand({
      Session: session,
      UserCode: code,
      FriendlyDeviceName: 'Authenticator',
    }));
    if (verify.Status !== 'SUCCESS') return res.status(401).json({ error: 'TOTP verify failed' });

    const resp = await cognito.send(new RespondToAuthChallengeCommand({
      ClientId: CLIENT_ID,
      ChallengeName: 'MFA_SETUP',
      Session: session,
      ChallengeResponses: { USERNAME: email },
    }));

    await publishSNS('MFA setup completed', `MFA TOTP enrolled for ${email}`);

    if (resp.ChallengeName === 'SOFTWARE_TOKEN_MFA') {
      return res.json({ challengeName: 'SOFTWARE_TOKEN_MFA', session: resp.Session, message: 'Enter your TOTP code' });
    }
    return res.json({ message: 'MFA setup complete. Please sign in.' });
  } catch (err) {
    console.error('MFA setup verify error:', err);
    if (err?.name === 'NotAuthorizedException') {
      return res.status(401).json({
        error: 'Thank you, please login again.',
        redirect: true
      });
    }
    res.status(401).json({ error: 'MFA setup failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase().trim();
    const password = req.body?.password || '';
    if (!email || !password) return res.status(400).json({ error: 'Missing email/password' });

    const init = await cognito.send(new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password },
    }));

    if (init.ChallengeName === 'SOFTWARE_TOKEN_MFA' || init.ChallengeName === 'SMS_MFA') {
      return res.json({ challengeName: init.ChallengeName, session: init.Session, message: 'MFA required' });
    }
    if (init.ChallengeName === 'MFA_SETUP') {
      return res.json({ challengeName: 'MFA_SETUP', session: init.Session, message: 'MFA setup required' });
    }

    const appToken = signToken({ sub: email, email, src: 'cognito' });
    await publishSNS('Login success', `User ${email} logged in`);
    return res.json({ message: 'Login success', accessToken: appToken, user: { email } });
  } catch (err) {
    console.error('Cognito login error:', err);
    if (err?.name === 'UserNotConfirmedException') {
      return res.status(403).json({ error: 'Email not verified', code: 'USER_NOT_CONFIRMED' });
    }
    return res.status(401).json({ error: 'Login failed' });
  }
});

app.post('/login/mfa', async (req, res) => {
  try {
    const email = (req.body?.email || '').toLowerCase().trim();
    const code = (req.body?.code || '').trim();
    const session = req.body?.session;
    const challengeName = req.body?.challengeName;
    if (!email || !code || !session || !challengeName) {
      return res.status(400).json({ error: 'Missing email/code/session/challengeName' });
    }

    const resp = await cognito.send(new RespondToAuthChallengeCommand({
      ClientId: CLIENT_ID,
      ChallengeName: challengeName,
      Session: session,
      ChallengeResponses: {
        USERNAME: email,
        SMS_MFA_CODE: code,
        SOFTWARE_TOKEN_MFA_CODE: code,
      },
    }));

    if (!resp?.AuthenticationResult?.AccessToken) {
      return res.status(401).json({ error: 'MFA failed' });
    }

    const appToken = signToken({ sub: email, email, src: 'cognito' });
    await publishSNS('Login success', `User ${email} logged in`);
    return res.json({ message: 'Login success (MFA)', accessToken: appToken, user: { email } });
  } catch (err) {
    console.error('MFA error:', err);
    res.status(401).json({ error: 'MFA failed' });
  }
});

/* ========= S3 + SQS ========= */

const ipOf = (req) => req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';

app.post('/files/presign/upload', authRequired, async (req, res) => {
  try {
    const { fileName, contentType, size } = req.body || {};
    if (!fileName) return res.status(400).json({ error: 'Missing fileName' });

    const safeName = sanitize(fileName);
    const key = `${userPrefix(req)}${Date.now()}_${safeName}`;

    const cmd = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      ContentType: contentType || 'application/octet-stream',
      ServerSideEncryption: 'AES256',
    });

    const uploadUrl = await getSignedUrl(s3, cmd, { expiresIn: 60 * 5 });

    await sendSQS('upload_initiated', {
      email: req.user?.email,
      key,
      contentType: contentType || 'application/octet-stream',
      size: Number(size) || 0,
      ip: ipOf(req),
    });

    res.json({ uploadUrl, key });
  } catch (err) {
    console.error('Presign upload error:', err);
    res.status(500).json({ error: 'Failed to create upload URL' });
  }
});

app.post('/files/notify-upload', authRequired, async (req, res) => {
  try {
    const key = String(req.body?.key || '');
    const size = Number(req.body?.size || 0);
    if (!key) return res.status(400).json({ error: 'Missing key' });
    if (!key.startsWith(userPrefix(req))) return res.status(403).json({ error: 'Forbidden key' });

    await sendSQS('upload_completed', {
      email: req.user?.email,
      key,
      size,
      ip: ipOf(req),
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('Notify upload error:', err);
    res.status(500).json({ error: 'Failed to record upload completion' });
  }
});

app.get('/files/list', authRequired, async (req, res) => {
  try {
    const Prefix = userPrefix(req);
    let ContinuationToken;
    const all = [];
    do {
      const out = await s3.send(new ListObjectsV2Command({
        Bucket: BUCKET_NAME,
        Prefix,
        ContinuationToken,
        MaxKeys: 1000,
      }));
      (out.Contents || []).forEach(o =>
        all.push({ key: o.Key, size: o.Size, lastModified: o.LastModified })
      );
      ContinuationToken = out.IsTruncated ? out.NextContinuationToken : undefined;
    } while (ContinuationToken);

    res.json({ items: all });
  } catch (err) {
    console.error('List files error:', err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});

app.get('/files/presign/view', authRequired, async (req, res) => {
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

app.get('/files/presign/download', authRequired, async (req, res) => {
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

// NEW: Delete object (scoped to user's prefix)
app.delete('/files/delete', authRequired, async (req, res) => {
  try {
    const key = String(req.query.key || '');
    if (!key) return res.status(400).json({ error: 'Missing key' });
    const prefix = userPrefix(req);
    if (!key.startsWith(prefix)) return res.status(403).json({ error: 'Forbidden key' });

    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: key }));

    await sendSQS('delete_object', {
      email: req.user?.email,
      key,
      ip: ipOf(req),
    });

    res.json({ ok: true, deleted: key });
  } catch (err) {
    console.error('Delete file error:', err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

/* ========= START ========= */
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ API http://0.0.0.0:${PORT}`);
  console.log(`🔐 Cognito enforced (email OTP + MFA)`);
  console.log(`🪣 S3: s3://${BUCKET_NAME} (${S3_REGION})`);
  console.log(`📣 SNS: ${sns ? 'enabled' : 'disabled'} | 📨 SQS: ${sqs ? 'enabled' : 'disabled'}`);
  console.log(`🔓 CORS: ${[...ALLOW_SET].join(', ')}`);
});
