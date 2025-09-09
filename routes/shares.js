import { Router } from "express";
import { ddb } from "../config/aws.js";
import { env } from "../config/env.js";
import { PutCommand, GetCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";
import { getFileById, hasAccess, writeAudit } from "../services/dynamo.js";
import { nanoid } from "nanoid";

const r = Router();

r.post("/", async (req, res) => {
  const user = req.user;
  const { fileId, expiresInSeconds, password } = req.body || {};
  const meta = await getFileById(user.orgId, fileId);
  if (!meta) return res.status(404).json({ error: "Not found" });

  const canShare = user.roles.includes("org_admin")
    || user.sub === meta.uploaderId
    || await hasAccess(fileId, user.sub, "OWNER");
  if (!canShare) return res.status(403).json({ error: "Forbidden" });

  const ttl = Math.min(expiresInSeconds || 3600, env.shareLinkTtl);
  const shareId = nanoid(16);
  await ddb.send(new PutCommand({
    TableName: env.tables.acl,
    Item: {
      PK: `SHARE#${shareId}`,
      SK: "META",
      orgId: user.orgId,
      fileId,
      createdBy: user.sub,
      passwordHash: password ? await hash(password) : null,
      ttl: Math.floor(Date.now()/1000) + ttl
    }
  }));
  await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "SHARE_CREATE", targetType: "FILE", targetId: fileId, outcome: "OK" });
  res.json({ shareId, expiresIn: ttl });
});

r.get("/:shareId", async (req, res) => {
  const { shareId } = req.params;
  const password = req.query.password;
  const rr = await ddb.send(new GetCommand({
    TableName: env.tables.acl,
    Key: { PK: `SHARE#${shareId}`, SK: "META" }
  }));
  const item = rr.Item;
  if (!item) return res.status(404).json({ error: "Invalid share" });
  if (item.ttl < Math.floor(Date.now()/1000)) return res.status(410).json({ error: "Expired" });

  if (item.passwordHash) {
    if (!password || !(await verify(password, item.passwordHash))) {
      return res.status(401).json({ error: "Password required/invalid" });
    }
  }
  res.json({ orgId: item.orgId, fileId: item.fileId });
});

r.delete("/:shareId", async (req, res) => {
  const user = req.user;
  const { shareId } = req.params;
  const rr = await ddb.send(new GetCommand({
    TableName: env.tables.acl,
    Key: { PK: `SHARE#${shareId}`, SK: "META" }
  }));
  const item = rr.Item;
  if (!item) return res.status(404).json({ error: "Not found" });
  if (item.orgId !== user.orgId) return res.status(403).json({ error: "Forbidden" });
  await ddb.send(new DeleteCommand({
    TableName: env.tables.acl,
    Key: { PK: `SHARE#${shareId}`, SK: "META" }
  }));
  await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "SHARE_DELETE", targetType: "FILE", targetId: item.fileId, outcome: "OK" });
  res.json({ ok: true });
});

async function hash(s) {
  const data = new TextEncoder().encode(s);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(buf).toString("hex");
}
async function verify(s, h) {
  return (await hash(s)) === h;
}

export default r;
