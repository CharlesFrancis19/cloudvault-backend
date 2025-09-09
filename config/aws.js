import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { S3Client } from "@aws-sdk/client-s3";
import { KMSClient } from "@aws-sdk/client-kms";
import { SNSClient } from "@aws-sdk/client-sns";
import { SESClient } from "@aws-sdk/client-ses";
import { env } from "./env.js";

export const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: env.region }), {
  marshallOptions: { removeUndefinedValues: true }
});
export const s3 = new S3Client({ region: env.region });
export const kms = new KMSClient({ region: env.region });
export const sns = new SNSClient({ region: env.region });
export const ses = new SESClient({ region: env.region });
