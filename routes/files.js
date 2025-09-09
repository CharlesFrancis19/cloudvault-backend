import { Router } from "express";
import { nanoid } from "nanoid";
import { getPresignedPutUrl, getPresignedGetUrl } from "../services/s3.js";
import { saveFileMeta, getFileById, addAcl, hasAccess, writeAudit, getOrgPolicy } from "../services/dynamo.js";

const r = Router();

r.post("/presign/upload", async (req, res) => {
  const user = req.user;
  const { fileName, contentType, size } = req.body || {};
  const policy = await getOrgPolicy(user.orgId);

  if (size > policy.maxFileSizeMB * 1024 * 1024) {
    await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "UPLOAD_DENY_SIZE", targetType: "FILE", outcome: "DENY" });
    return res.status(413).json({ error: "File too large" });
  }
  if (policy.blockedMimeTypes.includes(contentType)) {
    await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "UPLOAD_DENY_MIME", targetType: "FILE", outcome: "DENY" });
    return res.status(415).json({ error: "Blocked file type" });
  }

  const { url, key } = await getPresignedPutUrl({
    orgId: user.orgId, userId: user.sub, fileName, contentType
  });

  const fileId = nanoid();
  await saveFileMeta({
    orgId: user.orgId,
    fileId,
    s3Key: key,
    name: fileName,
    size,
    mime: contentType,
    uploaderId: user.sub,
    createdAt: new Date().toISOString()
  });
  await addAcl(fileId, user.sub, "OWNER");
  await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "UPLOAD_PRESIGN_ISSUED", targetType: "FILE", targetId: fileId, outcome: "OK" });

  res.json({ uploadUrl: url, fileId, s3Key: key });
});

r.get("/:fileId/presign/download", async (req, res) => {
  const user = req.user;
  const fileId = req.params.fileId;
  const meta = await getFileById(user.orgId, fileId);
  if (!meta) return res.status(404).json({ error: "Not found" });

  const allowed = user.roles.includes("org_admin")
    || user.sub === meta.uploaderId
    || await hasAccess(fileId, user.sub, "READ");

  if (!allowed) {
    await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "DOWNLOAD_DENY", targetType: "FILE", targetId: fileId, outcome: "DENY" });
    return res.status(403).json({ error: "Forbidden" });
  }

  const { url } = await getPresignedGetUrl(meta.s3Key);
  await writeAudit({ orgId: user.orgId, actorId: user.sub, action: "DOWNLOAD_URL_ISSUED", targetType: "FILE", targetId: fileId, outcome: "OK" });
  res.json({ downloadUrl: url, name: meta.name, mime: meta.mime, size: meta.size });
});

export default r;
