import { s3 } from "../config/aws.js";
import { env } from "../config/env.js";
import { GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

export async function getPresignedPutUrl({ orgId, userId, fileName, contentType }) {
  const key = `${orgId}/${userId}/${crypto.randomUUID()}-${sanitize(fileName)}`;
  const cmd = new PutObjectCommand({
    Bucket: env.bucket,
    Key: key,
    ContentType: contentType,
    ServerSideEncryption: "aws:kms",
    SSEKMSKeyId: env.kmsKeyId,
    Metadata: { orgId, uploaderId: userId }
  });
  const url = await getSignedUrl(s3, cmd, { expiresIn: 900 });
  return { url, key };
}

export async function getPresignedGetUrl(key) {
  const cmd = new GetObjectCommand({ Bucket: env.bucket, Key: key, ResponseCacheControl: "no-store" });
  const url = await getSignedUrl(s3, cmd, { expiresIn: 900 });
  return { url };
}

function sanitize(name) {
  return name.replace(/[^\w.\-]/g, "_");
}
