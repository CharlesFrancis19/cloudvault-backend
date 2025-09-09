import { Router } from "express";
import { env } from "../config/env.js";
import { signDevJwt } from "../utils/jwt.js";

const r = Router();

/**
 * POST /auth/dev-login
 * body: { email, password }
 * In DEV mode, returns a signed JWT with fake user info and roles from env.DEFAULT_ROLES.
 */
r.post("/dev-login", async (req, res) => {
  if (env.authMode !== 'DEV_JWT') {
    return res.status(400).json({ error: "DEV_JWT mode is disabled" });
  }
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email/password required" });

  // simple demo check; customize as needed
  const sub = `user-${Buffer.from(email).toString('hex').slice(0, 12)}`;
  const token = await signDevJwt({
    sub,
    email,
    name: email.split('@')[0],
    orgId: env.defaultOrgId,
    roles: env.defaultRoles
  });
  res.json({ accessToken: token });
});

export default r;
