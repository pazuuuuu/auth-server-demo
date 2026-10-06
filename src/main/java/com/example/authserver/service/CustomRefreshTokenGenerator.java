package com.example.authserver.service;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

public class CustomRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private static final Logger log = LoggerFactory.getLogger(CustomRefreshTokenGenerator.class);

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Duration timeToLive = context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive();
        
        // Custom Logic: Extend expiration if 'mobile_access' scope is present
        if (context.getAuthorizedScopes().contains("mobile_access")) {
            timeToLive = Duration.ofDays(30);
        }
        
        Instant expiresAt = issuedAt.plus(timeToLive);
        log.debug("refresh TTL {} (scopes {})", timeToLive, context.getAuthorizedScopes());
        return new OAuth2RefreshToken(UUID.randomUUID().toString(), issuedAt, expiresAt);
    }
}
