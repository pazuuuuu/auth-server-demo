# Spring Authorization Server Demo

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
  - **NIST-compliant Password Validation**: Checks for length, common passwords, and complexity.
- **Forgot Password Flow**
  - Secure email-based password reset simulation (logs output).
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

2. **Run the application**
   ```bash
   ./mvnw spring-boot:run
   ```
   The server will start at `http://localhost:8080`.

3. **Verify Installation**
   - **Discovery Endpoint**: [http://localhost:8080/.well-known/openid-configuration](http://localhost:8080/.well-known/openid-configuration)
   - **Login Page**: [http://localhost:8080/login](http://localhost:8080/login)

## Testing

### OIDC Flow
You can use [OIDC Debugger](https://oidcdebugger.com/) to test the authentication flow:
- **Authorize URI**: `http://localhost:8080/oauth2/authorize`
- **Client ID**: `oidc-client`
- **Scope**: `openid profile mobile_access` (Add `mobile_access` to test long-lived tokens)
- **PKCE**: `S256`

### Passkey (WebAuthn)
1. Log in with default credentials (`user` / `password`).
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
