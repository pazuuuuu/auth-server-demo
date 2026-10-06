# Spring Authorization Server Demo

[![CI](https://github.com/pazuuuuu/auth-server-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/pazuuuuu/auth-server-demo/actions/workflows/ci.yml)

A secure, customizable Authentication Server built with **Spring Boot 3** and **Spring Authorization Server**.
This project demonstrates a production-ready OIDC provider implementation with advanced security features.

## Features

- **OpenID Connect (OIDC) Provider**
  - Authorization Code Flow with PKCE
  - Custom Consent Page support (extensible)
- **Custom Login UI**
  - Styled with Thymeleaf and CSS
  - Responsive design
- **Advanced Security**
  - **Scope-based Refresh Token Expiration**: Tokens with `mobile_access` scope last 30 days; others follow default policy.
  - **NIST SP 800-63B-style Password Validation**: Checks length and a blocklist of common passwords (no composition rules).
- **Forgot Password Flow**
  - Secure email-based password reset simulation (in the `dev` profile the reset link is written to the log; other profiles send nothing until a mail notifier is configured).
  - Token-based verification.
- **Passkey (WebAuthn) Support**
  - Passwordless login using Touch ID, Face ID, or YubiKey.
  - Seamless integration with Spring Security WebAuthn.

## Prerequisites

- **Java 17** or higher
- **Maven** (Wrapper included)

## Getting Started

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd auth-server
   ```

2. **Set the environment variables** (see `.env.example`)
   | Variable | Required | Notes |
   |---|---|---|
   | `DB_URL` / `DB_USERNAME` / `DB_PASSWORD` | yes | PostgreSQL (Supabase) |
   | `OIDC_CLIENT_SECRET` | yes | secret of the demo client `oidc-client`; at least 32 random characters (the app refuses to start otherwise) |
   | `APP_BASE_URL` | in production | public base URL used in password reset links (defaults to `http://localhost:8080`) |
   | `SPRING_PROFILES_ACTIVE=dev` | development only | DEBUG logs, the demo user, and reset links written to the log |
   | `DEMO_USER_PASSWORD` | development only | password of the demo user `user` (dev profile) |

3. **Run the application**
   ```bash
   ./mvnw spring-boot:run
   ```
   The server will start at `http://localhost:8080`.

4. **Verify Installation**
   - **Discovery Endpoint**: [http://localhost:8080/.well-known/openid-configuration](http://localhost:8080/.well-known/openid-configuration)
   - **Login Page**: [http://localhost:8080/login](http://localhost:8080/login)

## Testing

### Automated tests / CI
```bash
./mvnw verify
```
Tests use an in-memory H2 database (`src/test/resources/application.properties`), so no Supabase credentials are needed.
GitHub Actions (`.github/workflows/ci.yml`) runs the same command on every pull request and every push to `main`.

### OIDC Flow
You can use [OIDC Debugger](https://oidcdebugger.com/) to test the authentication flow:
- **Authorize URI**: `http://localhost:8080/oauth2/authorize`
- **Client ID**: `oidc-client`
- **Scope**: `openid profile mobile_access` (Add `mobile_access` to test long-lived tokens)
- **PKCE**: `S256` (required — the client is registered with `requireProofKey(true)`)
- **Client secret**: the value of `OIDC_CLIENT_SECRET`

### Passkey (WebAuthn)
1. Run with the `dev` profile and log in as `user` with the password you set in `DEMO_USER_PASSWORD` (see `.env.example`; the demo user is created only in the `dev` profile).
2. On the Welcome page, click **Register Passkey**.
3. Log out and use **Sign in with Passkey** on the login screen.

## Troubleshooting

### Passkey Issues
- **Registration Failed**: Check server logs. Ensure the JSON payload matches the server's `RelyingPartyPublicKey` structure.
- **Login 404**: Ensure the client is using `/webauthn/authenticate/options` (not `/login/webauthn/options`).
- **Login 403**: Ensure the "Sign in with Passkey" button is `type="button"` to prevent form submission.
- **Bad Origin**: Passkeys require HTTPS or `localhost`. Ensure `allowedOrigins` in `SecurityConfig` includes your origin.

## License
MIT
