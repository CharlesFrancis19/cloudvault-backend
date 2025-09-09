import { Router } from "express";
import { ddb } from "../config/aws.js";
import { env } from "../config/env.js";
import { QueryCommand } from "@aws-sdk/lib-dynamodb";

const r = Router();

r.get("/", async (req, res) => {
  const user = req.user;
  const from = req.query.from || "0000-00-00T00:00:00.000Z";
  const to = req.query.to || "9999-12-31T23:59:59.999Z";

  const q = await ddb.send(new QueryCommand({
    TableName: env.tables.audit,
    KeyConditionExpression: "PK = :pk AND SK BETWEEN :from AND :to",
    ExpressionAttributeValues: {
      ":pk": `ORG#${user.orgId}`,
      ":from": `TS#${from}`,
      ":to": `TS#${to}`
    },
    ScanIndexForward: false,
    Limit: 200
  }));
  res.json({ events: q.Items || [] });
});

export default r;
