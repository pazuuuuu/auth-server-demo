package com.example.authserver.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Clock;
import java.util.UUID;

import com.example.authserver.data.RotatedRefreshTokenRepository;
import com.example.authserver.service.RefreshTokenReuseDetectingAuthorizationService;

import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.boot.ApplicationRunner;

@Configuration
public class AuthorizationServerConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * デモ用クライアントを登録する。既にあれば同じ id のまま設定を上書きする（設定を直したら既存の DB にも効かせる）。
     * シークレットは環境変数 OIDC_CLIENT_SECRET から受け取り（32文字以上でなければ起動しない）、PasswordEncoder で encode して保存する。
     */
    @Bean
    public ApplicationRunner clientLoader(RegisteredClientRepository repository, PasswordEncoder passwordEncoder,
            @Value("${app.oidc-client.secret}") String clientSecret) {
        requireStrongSecret(clientSecret);
        return args -> {
            String clientId = "oidc-client";
            RegisteredClient existing = repository.findByClientId(clientId);
            String id = existing != null ? existing.getId() : UUID.randomUUID().toString();
            RegisteredClient oidcClient = RegisteredClient.withId(id)
                    .clientId(clientId)
                    .clientSecret(passwordEncoder.encode(clientSecret))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                    .redirectUri("https://oidcdebugger.com/debug")
                    .postLogoutRedirectUri("http://127.0.0.1:8080/")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("mobile_access")
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(true)
                            .requireProofKey(true)          // 機密クライアントも PKCE 必須（RFC 9700 §2.1.1）
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .reuseRefreshTokens(false)      // 使い回さない＝漏えいの検知。見つけたら失効（RFC 9700 §4.14・RefreshTokenReuseDetectingAuthorizationService）
                            .build())
                    .build();
            repository.save(oidcClient);
        };
    }

    static final int MIN_CLIENT_SECRET_LENGTH = 32;

    /** 空・短い・テンプレートのままのシークレットでは起動しない（Basic 認証が弱い値で通るのを防ぐ）。 */
    static void requireStrongSecret(String clientSecret) {
        if (clientSecret == null || clientSecret.isBlank() || clientSecret.length() < MIN_CLIENT_SECRET_LENGTH
                || clientSecret.startsWith("change-me")) {
            throw new IllegalStateException("OIDC_CLIENT_SECRET must be set to a random value of at least "
                    + MIN_CLIENT_SECRET_LENGTH + " characters");
        }
    }

    /** 保存は JDBC。リフレッシュトークンの使い回しを見つけたら authorization を丸ごと失効させる（RFC 9700 §4.14.2・docs/harness.md §7.6）。 */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository, RotatedRefreshTokenRepository rotatedRefreshTokens) {
        return new RefreshTokenReuseDetectingAuthorizationService(
                new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository), rotatedRefreshTokens, Clock.systemUTC());
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 署名鍵。環境変数 JWT_SIGNING_KEY（PKCS#8 の PEM）から読む。旧鍵の公開鍵は JWT_PREVIOUS_PUBLIC_KEYS（任意）。
     * 鍵が無いと起動しない。dev プロファイルとテストだけ app.jwt.allow-ephemeral-key=true で起動ごとの鍵を許す（docs/SLO.md §7）。
     */
    @Bean
    public SigningKeys signingKeys(@Value("${app.jwt.signing-key:}") String signingKey,
            @Value("${app.jwt.previous-public-keys:}") String previousPublicKeys,
            @Value("${app.jwt.allow-ephemeral-key:false}") boolean allowEphemeral) {
        SigningKeys keys = SigningKeys.load(signingKey, previousPublicKeys, allowEphemeral);
        if (signingKey.isBlank()) {
            log.warn("JWT_SIGNING_KEY is not set; using a key generated for this process only (tokens become unverifiable after restart)");
        }
        log.info("JWT signing key id: {}", keys.currentKeyId());
        return keys;
    }

    /** JWKS（/oauth2/jwks）と、userinfo 等でアクセストークンを検証する JwtDecoder が使う鍵の集合（今の鍵＋旧鍵）。 */
    @Bean
    public JWKSource<SecurityContext> jwkSource(SigningKeys signingKeys) {
        return new ImmutableJWKSet<>(signingKeys.publishedSet());
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(SigningKeys signingKeys,
            OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer) {
        // 署名は今の鍵だけで行う（旧鍵は検証用に JWKS へ出すだけ）
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(new ImmutableJWKSet<>(signingKeys.signingSet())));
        jwtGenerator.setJwtCustomizer(tokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        com.example.authserver.service.CustomRefreshTokenGenerator refreshTokenGenerator = new com.example.authserver.service.CustomRefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                if (context.getPrincipal().getClass().getName().contains("WebAuthn")) {
                    log.debug("ACR: passkey");
                    context.getClaims().claim("acr", SecurityConstants.ACR_PASSKEY);
                } else if (context.getPrincipal() instanceof UsernamePasswordAuthenticationToken) {
                    log.debug("ACR: password");
                    context.getClaims().claim("acr", SecurityConstants.ACR_PASSWORD);
                }
            }
        };
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}
