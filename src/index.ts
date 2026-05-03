import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import { eq } from "drizzle-orm";
import JWT from "jsonwebtoken";
import jose from "node-jose";
import { db } from "./db";
import { applicationsTable, usersTable, authorizationCodesTable, authSessionsTable, refreshTokensTable } from "./db/schema";
import { PUBLIC_KEY } from "./utils/cert";
import type { JWTClaims } from "./utils/user-token";
import { issueTokens } from "./utils/generate-token";
import cookieParser from "cookie-parser";

const app = express();
const PORT = process.env.PORT ?? 8000;

app.use(express.json());
app.use(express.static(path.resolve("public")));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.get("/", (req, res) => res.json({ message: "Hello from Auth Server" }));

app.get("/health", (req, res) =>
  res.json({ message: "Server is healthy", healthy: true }),
);

// OIDC Endpoints
app.get("/.well-known/openid-configuration", (req, res) => {
  const ISSUER = `http://localhost:${PORT}`;
  return res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/o/authenticate`,
    token_endpoint: `${ISSUER}/o/token`,
    userinfo_endpoint: `${ISSUER}/o/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  });
});

app.get("/.well-known/jwks.json", async (_, res) => {
  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
  return res.json({ keys: [key.toJSON()] });
});

app.post("/o/token", async (req, res) => {
  const { 
    grant_type,
    code,
    client_id, 
    client_secret, 
    redirect_uri, 
    refresh_token,
  } = req.body;

  if (!client_id || !client_secret) {
    return res.status(400).json({ message: "invalid client" });
  }

  const [client] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientId, client_id))
    .limit(1);

  const clientSecretHash = crypto
  .createHash("sha256")
  .update(client_secret)
  .digest("hex");

  if (!client || client.clientSecretHash !== clientSecretHash) {
    return res.status(401).json({ message: "invalid client" });
  }

  const ISSUER = `http://localhost:${PORT}`;
  const now = Math.floor(Date.now() / 1000);

  
  if (!grant_type) {
    return res.status(400).json({ message: "missing grant_type" });
  }

  // using refreshToken
  if (grant_type === "refresh_token") {
    if (!refresh_token) {
      return res.status(400).json({ message: "missing refresh_token" });
    }
    const hashed = crypto
      .createHash("sha256")
      .update(refresh_token)
      .digest("hex");

    const [stored] = await db
      .select()
      .from(refreshTokensTable)
      .where(eq(refreshTokensTable.tokenHash, hashed))
      .limit(1);

    if (
      !stored ||
      stored.expiresAt < new Date() ||
      stored.revokedAt ||
      stored.applicationId !== client.id
    ) {
      return res.status(401).json({ message: "invalid refresh token" });
    }

    const userId = stored.userId;

    await db
      .update(refreshTokensTable)
      .set({ revokedAt: new Date() })
      .where(eq(refreshTokensTable.tokenHash, hashed));

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, userId))
      .limit(1);

    if (!user) {
      return res.status(401).json({ message: "user not found" });
    }
      
    return issueTokens({
      user,
      client,
      ISSUER,
      now,
      res,
    });
  }

  // using code
  if (grant_type === "authorization_code") {
    if (!code || !redirect_uri) {
      return res.status(400).json({ message: "invalid request" });
    }

    const hashedCode = crypto
      .createHash("sha256")
      .update(code)
      .digest("hex");

    const [authCode] = await db
      .select()
      .from(authorizationCodesTable)
      .where(eq(authorizationCodesTable.codeHash, hashedCode))
      .limit(1);

    if (
      !authCode ||
      authCode.expiresAt < new Date() ||
      authCode.usedAt ||
      authCode.applicationId !== client.id
    ) {
      return res.status(401).json({ message: "invalid code" });
    }

    if (authCode.redirectUri !== redirect_uri) {
      return res.status(400).json({ message: "redirect_uri mismatch" });
    }

    await db
      .update(authorizationCodesTable)
      .set({ usedAt: new Date() })
      .where(eq(authorizationCodesTable.id, authCode.id));

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, authCode.userId))
      .limit(1);

    if (!user) {
      return res.status(401).json({ message: "user not found" });
    }

    return issueTokens({
      user,
      client,
      ISSUER,
      now,
      res,
      nonce: authCode.nonce,
    });
  }

  return res.status(400).json({ message: "unsupported grant_type" });
})

app.get("/o/authenticate", async (req, res) => {
  const { client_id, redirect_uri, state, nonce } = req.query;
  const clientId = typeof client_id === "string" ? client_id : null;
  const redirectUri = typeof redirect_uri === "string" ? redirect_uri : null;

  if (!clientId || !redirectUri) {
    return res.status(400).json({ message: "missing parameters" });
  }
  
  const [client] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientId, clientId))
    .limit(1);

  if (!client) {
    return res.status(400).json({ message: "application not found" });
  }

  if (client.redirectUri !== redirectUri) {
    return res.status(400).json({ message: "invalid redirect uri" });
  }

  const rawToken = req.cookies?.auth_session;

  if (!rawToken) {
    return res.sendFile(path.resolve("public", "authenticate.html"));
  }

  const sessionHash = crypto
    .createHash("sha256")
    .update(rawToken)
    .digest("hex");

  const [session] = await db
    .select()
    .from(authSessionsTable)
    .where(eq(authSessionsTable.sessionHash, sessionHash))
    .limit(1);

  if (!session || session.expiresAt < new Date()) {
    return res.sendFile(path.resolve("public", "authenticate.html"));
  }
  
  return res.sendFile(path.resolve("public", "application.html"));
});

app.get("/o/authenticate/application", async (req, res) => {
  const { client_id, redirect_uri } = req.query;
  const clientId = typeof client_id === "string" ? client_id : null;
  const redirectUri = typeof redirect_uri === "string" ? redirect_uri : null;

  if (!clientId || !redirectUri) {
    return res.status(400).json({ message: "missing parameters" });
  }
  
  const [client] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientId, clientId))
    .limit(1);

  if (!client) {
    return res.status(400).json({ message: "application not found" });
  }

  if (client.redirectUri !== redirectUri) {
    return res.status(400).json({ message: "invalid redirect uri" });
  }

  return res.json({ name: client.name });
});

app.post("/o/authenticate/consent", async (req, res) => {
  const { client_id, redirect_uri, state, nonce } = req.body;

  if (!client_id || !redirect_uri) {
    return res.status(400).json({ message: "missing parameters" });
  }
  
  const [client] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientId, client_id))
    .limit(1);

  if (!client) {
    return res.status(400).json({ message: "application not found" });
  }

  if (client.redirectUri !== redirect_uri) {
    return res.status(400).json({ message: "invalid redirect uri" });
  }

  const rawToken = req.cookies?.auth_session;

  if (!rawToken) {
    return res.status(401).json({ message: "not authenticated" });
  }

  const sessionHash = crypto
    .createHash("sha256")
    .update(rawToken)
    .digest("hex");

  const [session] = await db
    .select()
    .from(authSessionsTable)
    .where(eq(authSessionsTable.sessionHash, sessionHash))
    .limit(1);

  if (!session || session.expiresAt < new Date()) {
    return res.status(401).json({ message: "not authenticated" });
  }

  const userId = session.userId;

  const code = crypto.randomBytes(32).toString("hex");
  const codeHash = crypto
    .createHash("sha256")
    .update(code)
    .digest("hex");

  await db.insert(authorizationCodesTable).values({
    codeHash,
    userId,
    applicationId: client.id,
    redirectUri: redirect_uri,
    nonce: nonce ?? null,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 mins
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if(state) redirectUrl.searchParams.set("state", state);

  return res.json({ redirect: redirectUrl.toString() });
});

app.post("/o/authenticate/sign-in", async (req, res) => {
  const { email, password, client_id, redirect_uri, state, nonce } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required." });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (!user || !user.password || !user.salt) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  const hash = crypto
    .createHash("sha256")
    .update(password + user.salt)
    .digest("hex");

  if (hash !== user.password) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  const token = crypto.randomBytes(32).toString("hex");

  const sessionHash = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

  await db.insert(authSessionsTable).values({
    userId: user.id,
    sessionHash,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    createdAt: new Date(),
  });

  res.cookie("auth_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  })

  if(client_id && redirect_uri){
    const [client] = await db
      .select()
      .from(applicationsTable)
      .where(eq(applicationsTable.clientId, client_id))
      .limit(1);

    if (!client || client.redirectUri !== redirect_uri) {
      return res.status(400).json({ message: "invalid client" });
    }

    const authorizeParams = new URLSearchParams({
      client_id,
      redirect_uri,
    });

    if (state) authorizeParams.set("state", state);
    if (nonce) authorizeParams.set("nonce", nonce);

    return res.json({ redirect: `/o/authenticate?${authorizeParams.toString()}` });
  }

  return res.json({ success: true });
});

app.post("/o/authenticate/sign-up", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!email || !password || !firstName) {
    res
      .status(400)
      .json({ message: "First name, email, and password are required." });
    return;
  }

  const [existing] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing) {
    res
      .status(409)
      .json({ message: "An account with this email already exists." });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest("hex");

  await db.insert(usersTable).values({
    firstName,
    lastName: lastName ?? null,
    email,
    password: hash,
    salt,
  });

  res.status(201).json({ ok: true });
});

app.get("/applications/register", (_, res) => {
  return res.sendFile(path.resolve("public", "register-application.html"));
});

app.post("/applications", async (req, res) => {
  const { name, redirect_uri } = req.body;

  const rawToken = req.cookies?.auth_session;

  if (!rawToken) {
    return res.status(401).json({ message: "Please sign in before registering an application." });
  }

  const sessionHash = crypto
    .createHash("sha256")
    .update(rawToken)
    .digest("hex");

  const [session] = await db
    .select()
    .from(authSessionsTable)
    .where(eq(authSessionsTable.sessionHash, sessionHash))
    .limit(1);

  if (!session || session.expiresAt < new Date()) {
    return res.status(401).json({ message: "Please sign in before registering an application." });
  }

  const appName = typeof name === "string" ? name.trim() : "";
  const redirectUri = typeof redirect_uri === "string" ? redirect_uri.trim() : "";

  if (!appName || appName.length > 100) {
    return res.status(400).json({ message: "Application name must be between 1 and 100 characters." });
  }

  let parsedRedirectUri: URL;
  try {
    parsedRedirectUri = new URL(redirectUri);
  } catch {
    return res.status(400).json({ message: "Redirect URI must be a valid absolute URL." });
  }

  if (!["http:", "https:"].includes(parsedRedirectUri.protocol)) {
    return res.status(400).json({ message: "Redirect URI must use http or https." });
  }

  if (parsedRedirectUri.hash) {
    return res.status(400).json({ message: "Redirect URI must not include a URL fragment." });
  }

  const isLocalhost =
    parsedRedirectUri.hostname === "localhost" ||
    parsedRedirectUri.hostname === "127.0.0.1" ||
    parsedRedirectUri.hostname === "::1";

  if (process.env.NODE_ENV === "production" && parsedRedirectUri.protocol !== "https:" && !isLocalhost) {
    return res.status(400).json({ message: "Redirect URI must use https outside localhost." });
  }

  const clientId = `client_${crypto.randomBytes(16).toString("hex")}`;
  const clientSecret = `secret_${crypto.randomBytes(32).toString("hex")}`;
  const clientSecretHash = crypto
    .createHash("sha256")
    .update(clientSecret)
    .digest("hex");

  await db.insert(applicationsTable).values({
    name: appName,
    clientId,
    clientSecretHash,
    redirectUri,
  });

  return res.status(201).json({
    name: appName,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
  });
});

app.get("/o/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    res
      .status(401)
      .json({ message: "Missing or invalid Authorization header." });
    return;
  }

  const token = authHeader.slice(7);

  let claims;
  try {
    claims = JWT.verify(token, PUBLIC_KEY, {
      algorithms: ["RS256"],
    }) as JWTClaims;
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  const ISSUER = `http://localhost:${PORT}`;
  if (claims.iss !== ISSUER) {
    return res.status(401).json({ message: "Invalid issuer" });
  }

  const [client] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientId, claims.aud))
    .limit(1);

  if (!client) {
    return res.status(401).json({ message: "Invalid audience" });
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, claims.sub))
    .limit(1);

  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    given_name: user.firstName,
    family_name: user.lastName,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL,
  });
});

app.listen(PORT, () => {
  console.log(`AuthServer is running on PORT ${PORT}`);

  // Ping mechanism to keep Render free tier awake
  const renderExternalUrl = process.env.RENDER_EXTERNAL_URL;
  if (renderExternalUrl) {
    const pingInterval = 14 * 60 * 1000; // 14 minutes
    setInterval(async () => {
      try {
        console.log(`Pinging ${renderExternalUrl}/health to keep awake...`);
        const res = await fetch(`${renderExternalUrl}/health`);
        if (res.ok) {
          console.log("Ping successful.");
        } else {
          console.log("Ping failed with status:", res.status);
        }
      } catch (err) {
        console.error("Ping error:", err);
      }
    }, pingInterval);
  }
});
