import 'dotenv/config';

export const env = {
  port: parseInt(process.env.PORT || '8080', 10),
  nodeEnv: process.env.NODE_ENV || 'development',

  authMode: process.env.AUTH_MODE || 'DEV_JWT', // DEV_JWT | COGNITO
  jwtSecret: process.env.JWT_HS256_SECRET || 'dev-secret',
  defaultOrgId: process.env.DEFAULT_ORG_ID || 'org-demo',
  defaultRoles: (process.env.DEFAULT_ROLES || 'user').split(','),

  region: process.env.AWS_REGION,
  bucket: process.env.AWS_S3_BUCKET,
  kmsKeyId: process.env.AWS_KMS_KEY_ID,

  cognito: {
    iss: process.env.COGNITO_ISS,
    clientId: process.env.COGNITO_CLIENT_ID,
  },

  tables: {
    filesMeta: process.env.DDB_FILES_META,
    acl: process.env.DDB_ACL,
    audit: process.env.DDB_AUDIT,
    users: process.env.DDB_USERS,
    orgs: process.env.DDB_ORGS
  },

  shareLinkTtl: parseInt(process.env.SHARE_LINK_TTL_SECONDS || '604800', 10)
};
