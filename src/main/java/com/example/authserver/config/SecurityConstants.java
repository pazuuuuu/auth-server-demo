package com.example.authserver.config;

public final class SecurityConstants {

    private SecurityConstants() {
        // Private constructor to prevent instantiation
    }

    public static final String LOGIN_URL = "/login";
    public static final String LOGIN_PROCESSING_URL = "/login";
    public static final String LOGOUT_URL = "/logout";
    public static final String ERROR_URL = "/error";

    // WebAuthn
    public static final String WEBAUTHN_PREFIX = "/webauthn/**";
    public static final String LOGIN_WEBAUTHN_PREFIX = "/login/webauthn/**";

    // Password Reset
    public static final String FORGOT_PASSWORD_PREFIX = "/forgot-password/**";
    public static final String RESET_PASSWORD_PREFIX = "/reset-password/**";

    // Static Resources
    public static final String CSS_Resources = "/css/**";
    public static final String IMAGES_Resources = "/images/**";

    public static final String RP_NAME = "Auth Server";
    public static final String RP_ID = "127.0.0.1";
    public static final String ALLOWED_ORIGIN = "http://127.0.0.1:8080";

    // ACR Values
    public static final String ACR_PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
    public static final String ACR_PASSKEY = "urn:oasis:names:tc:SAML:2.0:ac:classes:PublicKey";
}
