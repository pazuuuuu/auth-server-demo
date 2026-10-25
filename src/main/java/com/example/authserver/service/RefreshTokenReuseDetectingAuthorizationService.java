package com.example.authserver.service;

import com.example.authserver.data.RotatedRefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/**
 * リフレッシュトークンの使い回しを見つけたら、その authorization（アクセストークン・今のリフレッシュトークン・ID トークン）を丸ごと失効させる。
 * RFC 9700 §4.14.2：使い回しが来た時点で、正しいクライアントと攻撃者のどちらが持っているか区別できないため（docs/harness.md §7.6）。
 *
 * <p>Spring Authorization Server はローテーション（reuseRefreshTokens(false)）で古いトークンの記録を上書きするので、
 * 古いトークンが来ても「知らないトークン」としか分からない。ここで捨てたトークンのハッシュを覚えておき、見分ける。</p>
 *
 * <p>同じトークンで同時に2本の要求が来ると、どちらも検索の時点では「今のトークン」として引ける。そこで保存のときに
 * oauth2_authorization の行をロックし（SELECT … FOR UPDATE）、この要求が使ったトークンがまだ今のトークンかを比べる。
 * 先に別の要求がローテーションしていたら使い回しとして失効させ、この要求は invalid_grant にする（PR #11 Y1 案A）。</p>
 */
public class RefreshTokenReuseDetectingAuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenReuseDetectingAuthorizationService.class);

    /** この要求がトークンエンドポイントで使ったリフレッシュトークン（authorization ごと）。要求の属性に置くので要求が終われば消える。 */
    private static final String USED_REFRESH_TOKEN = RefreshTokenReuseDetectingAuthorizationService.class.getName() + ".used.";

    private final OAuth2AuthorizationService delegate;
    private final RotatedRefreshTokenRepository rotated;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;
    private final Clock clock;

    public RefreshTokenReuseDetectingAuthorizationService(OAuth2AuthorizationService delegate,
            RotatedRefreshTokenRepository rotated, JdbcTemplate jdbc, TransactionTemplate transaction, Clock clock) {
        this.delegate = delegate;
        this.rotated = rotated;
        this.jdbc = jdbc;
        this.transaction = transaction;
        this.clock = clock;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Boolean rotatedNow = transaction.execute(status -> {
            String current = lockCurrentRefreshToken(authorization.getId());
            OAuth2Authorization.Token<OAuth2RefreshToken> after = authorization.getRefreshToken();
            String next = after != null ? after.getToken().getTokenValue() : null;
            String used = usedRefreshToken(authorization.getId());
            if (current != null && used != null && !used.equals(next) && !used.equals(current)) {
                // この要求が使ったトークンは、検索の後に別の要求がローテーションした＝同時に来た使い回し
                revoke(authorization.getId(), authorization.getRegisteredClientId());
                return null;
            }
            if (current != null && !Objects.equals(current, next)) {
                OAuth2Authorization existing = delegate.findById(authorization.getId());
                OAuth2Authorization.Token<OAuth2RefreshToken> before = existing != null ? existing.getRefreshToken() : null;
                rotated.record(hash(current), authorization.getId(),
                        before != null ? before.getToken().getExpiresAt() : null, clock.instant());
                delegate.save(authorization);
                return true;
            }
            delegate.save(authorization);
            return false;
        });
        if (rotatedNow == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }
        if (rotatedNow) {
            rotated.purgeExpired(clock.instant());
        }
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
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return found;
        }
        if (found != null) {
            rememberUsedRefreshToken(found.getId(), token);
            return found;
        }
        // 捨てたリフレッシュトークンが来た＝使い回し。その authorization を消して、呼び出し側には「知らないトークン」（invalid_grant）を返す
        rotated.findAuthorizationId(hash(token)).map(delegate::findById)
                .ifPresent(reused -> revoke(reused.getId(), reused.getRegisteredClientId()));
        return null;
    }

    private void revoke(String authorizationId, String registeredClientId) {
        OAuth2Authorization reused = delegate.findById(authorizationId);
        if (reused == null) {
            return;
        }
        log.warn("Rotated refresh token was reused; revoking authorization id={} client={}", authorizationId, registeredClientId);
        remove(reused);
    }

    private String lockCurrentRefreshToken(String authorizationId) {
        List<String> rows = jdbc.queryForList(
                "SELECT refresh_token_value FROM oauth2_authorization WHERE id = ? FOR UPDATE", String.class, authorizationId);
        return rows.isEmpty() ? null : rows.get(0);
    }

    private static void rememberUsedRefreshToken(String authorizationId, String value) {
        RequestAttributes request = RequestContextHolder.getRequestAttributes();
        if (request != null) {
            request.setAttribute(USED_REFRESH_TOKEN + authorizationId, value, RequestAttributes.SCOPE_REQUEST);
        }
    }

    private static String usedRefreshToken(String authorizationId) {
        RequestAttributes request = RequestContextHolder.getRequestAttributes();
        return request != null ? (String) request.getAttribute(USED_REFRESH_TOKEN + authorizationId, RequestAttributes.SCOPE_REQUEST) : null;
    }

    static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
