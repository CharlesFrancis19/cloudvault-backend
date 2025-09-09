import { ddb } from "../config/aws.js";
import { env } from "../config/env.js";
import { PutCommand, GetCommand, QueryCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";

export async function saveFileMeta(meta) {
  await ddb.send(new PutCommand({
    TableName: env.tables.filesMeta,
    Item: {
      PK: `ORG#${meta.orgId}`,
      SK: `FILE#${meta.fileId}`,
      ...meta,
      GSI1PK: `UPLOADER#${meta.uploaderId}`,
      GSI1SK: meta.createdAt
    }
  }));
}

export async function getFileById(orgId, fileId) {
  const r = await ddb.send(new GetCommand({
    TableName: env.tables.filesMeta,
    Key: { PK: `ORG#${orgId}`, SK: `FILE#${fileId}` }
  }));
  return r.Item;
}

export async function addAcl(fileId, subjectId, perm) {
  await ddb.send(new PutCommand({
    TableName: env.tables.acl,
    Item: { PK: `FILE#${fileId}`, SK: `SUBJECT#${subjectId}`, perm }
  }));
}

export async function hasAccess(fileId, subjectId, must) {
  const r = await ddb.send(new GetCommand({
    TableName: env.tables.acl,
    Key: { PK: `FILE#${fileId}`, SK: `SUBJECT#${subjectId}` }
  }));
  const perm = r.Item?.perm || null;
  if (!perm) return false;
  if (must === "READ") return ["READ", "WRITE", "OWNER"].includes(perm);
  if (must === "WRITE") return ["WRITE", "OWNER"].includes(perm);
  if (must === "OWNER") return perm === "OWNER";
  return false;
}

export async function writeAudit(ev) {
  const ts = new Date().toISOString();
  await ddb.send(new PutCommand({
    TableName: env.tables.audit,
    Item: {
      PK: `ORG#${ev.orgId}`,
      SK: `TS#${ts}#${crypto.randomUUID()}`,
      ...ev, ts
    }
  }));
}

export async function getOrgPolicy(orgId) {
  const r = await ddb.send(new GetCommand({
    TableName: env.tables.orgs,
    Key: { PK: `ORG#${orgId}`, SK: "POLICY" }
  }));
  return r.Item?.policy || {
    maxFileSizeMB: 200,
    blockedMimeTypes: ["application/x-msdownload", "application/x-dosexec"],
    retentionDays: 365,
    requireMfa: true,
    shareLinks: { maxTtlHours: 168, allowPublic: false }
  };
}

export async function setOrgPolicy(orgId, policy) {
  await ddb.send(new PutCommand({
    TableName: env.tables.orgs,
    Item: { PK: `ORG#${orgId}`, SK: "POLICY", policy }
  }));
}
