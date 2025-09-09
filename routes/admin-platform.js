import { Router } from "express";
import { requireRole } from "../middleware/auth.js";
import { ddb } from "../config/aws.js";
import { env } from "../config/env.js";
import { PutCommand } from "@aws-sdk/lib-dynamodb";

const r = Router();

r.use(requireRole("platform_admin"));

r.post("/orgs", async (req, res) => {
  const { orgId, name } = req.body || {};
  await ddb.send(new PutCommand({
    TableName: env.tables.orgs,
    Item: { PK: `ORG#${orgId}`, SK: "META", name, status: "active" }
  }));
  res.json({ ok: true });
});

r.put("/orgs/:orgId/status", async (req, res) => {
  const { orgId } = req.params;
  const { status } = req.body || {};
  await ddb.send(new PutCommand({
    TableName: env.tables.orgs,
    Item: { PK: `ORG#${orgId}`, SK: "META", status }
  }));
  res.json({ ok: true });
});

export default r;
