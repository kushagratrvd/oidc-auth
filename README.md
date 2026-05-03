# OIDC Auth Server 🛡️

A custom-built, lightweight OpenID Connect (OIDC) compliant Authentication Provider. This server acts as a centralized Identity Provider (IdP) to offer secure Single Sign-On (SSO) capabilities, application registration, and OAuth2 authorization flows to other microservices.

## 🚀 Project Overview
This service manages users, authenticates them securely via sessions, and issues standardized OIDC tokens. It supports the **Authorization Code Flow**, allowing external applications (like the `1 million checkboxes` app) to securely delegate user login. 

## 🛠 Tech Stack
* **Runtime:** Node.js, Express
* **Database:** Drizzle ORM
* **Crypto:** Built-in `crypto` for securely hashing passwords & secrets, `jose` for JWKs/JWTs.
* **Views:** Static HTML served by Express

## ✨ Key Features
* **Standard OIDC Endpoints:** Implements `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/o/authenticate`, `/o/token`, and `/o/userinfo`.
* **Application Registry:** Developers can create an account and register their own Relying Party applications (generating `client_id` and `client_secret` pairs) via the `/applications/register` dashboard.
* **Authorization Code Grant:** Provides the widely-used, secure Authorization Code Flow for seamless third-party app logins.
* **Token Rotation:** Built-in support for generating, validating, and refreshing access configuration transparently.
* **Consent Screen:** Built-in UI to ensure users consent to sharing their basic profile info with registered applications.

## 💻 How to Run Locally

1. **Install dependencies:**
   ```bash
   pnpm install
   ```

2. **Generate Crypto Keys:**
   There is an included script (`key-gen.sh`) inside `oidc-auth` you must run to generate the RS256 PEM keys needed for the JSON Web Key Sets (JWKS).
   ```bash
   ./key-gen.sh
   # Or manually create private/public keys inside the /cert folder
   ```

3. **Start the Database / Migrations:**
   ```bash
   # Ensure you push the Drizzle schema to your DB
   npx drizzle-kit push:sqlite 
   ```

4. **Start the server:**
   ```bash
   pnpm run dev
   ```

5. **Register an App:**
   Navigate to `http://localhost:8000/applications/register` to register external applications and test the SSO flows.

## 🔐 Architecture Security Notes
*   **Password Hashing**: User passwords utilize secure, unique salts and are stored as SHA-256 hashes.
*   **Session Management**: Authentication sessions are maintained via HttpOnly cookies and cryptographically verified against the database.
*   **Public/Private Keys**: Tokens are standard JWTs digitally signed using RS256 so other applications can verify them asynchronously using the publicized JWKS endpoint.
