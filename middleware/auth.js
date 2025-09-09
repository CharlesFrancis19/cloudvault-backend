import { verifyAccessToken } from "../utils/jwt.js";

export async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });

    const payload = await verifyAccessToken(token);
    const roles = Array.isArray(payload["cognito:groups"]) ? payload["cognito:groups"] : [];
    const orgId = payload["custom:orgId"];
    if (!orgId) return res.status(403).json({ error: "No orgId in token" });

    req.user = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      orgId,
      roles
    };
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
}

export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!req.user.roles.includes(role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

export function sameOrgGuard(req, res, next) {
  const { orgId } = req.user || {};
  const targetOrgId = req.params.orgId || req.query.orgId || req.body.orgId;
  if (targetOrgId && targetOrgId !== orgId) {
    return res.status(403).json({ error: "Cross-tenant access denied" });
  }
  next();
}
