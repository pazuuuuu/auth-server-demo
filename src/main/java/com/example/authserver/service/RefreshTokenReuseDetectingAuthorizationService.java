package com.example.authserver.service;

import com.example.authserver.data.RotatedRefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.HexFormat;
import java.util.Objects;

/**
 * リフレッシュトークンの使い回しを見つけたら、その authorization（アクセストークン・今のリフレッシュトークン・ID トークン）を丸ごと失効させる。
 * RFC 9700 §4.14.2：使い回しが来た時点で、正しいクライアントと攻撃者のどちらが持っているか区別できないため（docs/harness.md §7.6）。
 *
 * <p>Spring Authorization Server はローテーション（reuseRefreshTokens(false)）で古いトークンの記録を上書きするので、
 * 古いトークンが来ても「知らないトークン」としか分からない。ここで捨てたトークンのハッシュを覚えておき、見分ける。</p>
 */
public class RefreshTokenReuseDetectingAuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenReuseDetectingAuthorizationService.class);

    private final OAuth2AuthorizationService delegate;
    private final RotatedRefreshTokenRepository rotated;
    private final Clock clock;

    public RefreshTokenReuseDetectingAuthorizationService(OAuth2AuthorizationService delegate,
            RotatedRefreshTokenRepository rotated, Clock clock) {
        this.delegate = delegate;
        this.rotated = rotated;
        this.clock = clock;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        OAuth2Authorization existing = delegate.findById(authorization.getId());
        OAuth2Authorization.Token<OAuth2RefreshToken> before = existing != null ? existing.getRefreshToken() : null;
        OAuth2Authorization.Token<OAuth2RefreshToken> after = authorization.getRefreshToken();
        if (before != null && (after == null
                || !Objects.equals(before.getToken().getTokenValue(), after.getToken().getTokenValue()))) {
            rotated.record(hash(before.getToken().getTokenValue()), authorization.getId(),
                    before.getToken().getExpiresAt(), clock.instant());
        }
        delegate.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        rotated.deleteByAuthorizationId(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2Authorization found = delegate.findByToken(token, tokenType);
        if (found != null || !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return found;
        }
        // 捨てたリフレッシュトークンが来た＝使い回し。その authorization を消して、呼び出し側には「知らないトークン」（invalid_grant）を返す
        rotated.findAuthorizationId(hash(token)).map(delegate::findById).ifPresent(reused -> {
            log.warn("Rotated refresh token was reused; revoking authorization id={} client={}",
                    reused.getId(), reused.getRegisteredClientId());
            remove(reused);
        });
        return null;
    }

    static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
