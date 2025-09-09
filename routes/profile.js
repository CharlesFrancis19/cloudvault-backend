import { Router } from "express";
import { ddb } from "../config/aws.js";
import { env } from "../config/env.js";
import { GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";

const r = Router();

r.get("/", async (req, res) => {
  const u = req.user;
  const r1 = await ddb.send(new GetCommand({
    TableName: env.tables.users,
    Key: { PK: `ORG#${u.orgId}`, SK: `USER#${u.sub}` }
  }));
  res.json({ profile: r1.Item || { email: u.email, name: u.name } });
});

r.put("/", async (req, res) => {
  const u = req.user;
  await ddb.send(new PutCommand({
    TableName: env.tables.users,
    Item: { PK: `ORG#${u.orgId}`, SK: `USER#${u.sub}`, ...req.body }
  }));
  res.json({ ok: true });
});

export default r;
