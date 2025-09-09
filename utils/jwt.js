import { SignJWT, jwtVerify, createRemoteJWKSet } from "jose";
import { env } from "../config/env.js";

let JWKS = null;
if (env.authMode === 'COGNITO') {
  JWKS = createRemoteJWKSet(new URL(`${env.cognito.iss}/.well-known/jwks.json`));
}

export async function signDevJwt({ sub, email, name, orgId, roles }) {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({
    sub, email, name,
    "custom:orgId": orgId,
    "cognito:groups": roles
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setIssuer('securevault-dev')
    .setAudience('securevault-dev-client')
    .setExpirationTime('2h')
    .sign(new TextEncoder().encode(env.jwtSecret));
}

export async function verifyAccessToken(token) {
  if (env.authMode === 'DEV_JWT') {
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(env.jwtSecret),
      { issuer: 'securevault-dev', audience: 'securevault-dev-client' }
    );
    return payload;
  } else {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: env.cognito.iss,
      audience: env.cognito.clientId
    });
    return payload;
  }
}
