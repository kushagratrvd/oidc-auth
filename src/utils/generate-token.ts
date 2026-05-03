import { db } from "../db";
import JWT from "jsonwebtoken";
import { PRIVATE_KEY } from "./cert";
import crypto from "node:crypto";
import { refreshTokensTable } from "../db/schema";

export async function issueTokens({
  user,
  client,
  ISSUER,
  now,
  res,
  nonce,
}: {
  user: any;
  client: any;
  ISSUER: string;
  now: number;
  res: any;
  nonce?: string | null;
}) {
  const accessClaims = {
    iss: ISSUER,
    sub: user.id,
    aud: client.clientId,
    iat: now,
    email: user.email,
    email_verified: user.emailVerified,
    exp: now + 3600,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
  };

  const idClaims = {
    iss: ISSUER,
    sub: user.id,
    aud: client.clientId,
    email: user.email,
    email_verified: user.emailVerified,
    iat: now,
    exp: now + 3600,
    nonce: nonce ?? undefined, 
  };

  const access_token = JWT.sign(accessClaims, PRIVATE_KEY, { algorithm: "RS256" });
  const refresh_token = crypto.randomBytes(32).toString("hex");
  const id_token = JWT.sign(idClaims, PRIVATE_KEY, { algorithm: "RS256" });

  const refreshHash = crypto
    .createHash("sha256")
    .update(refresh_token)
    .digest("hex");

  await db.insert(refreshTokensTable).values({
    tokenHash: refreshHash,
    userId: user.id,
    applicationId: client.id,
    expiresAt: new Date(Date.now() + 86400 * 1000),
    createdAt: new Date(),
  });

  return res.json({
    access_token,
    id_token,
    refresh_token,
    token_type: "Bearer",
    expires_in: 3600,
  });
}