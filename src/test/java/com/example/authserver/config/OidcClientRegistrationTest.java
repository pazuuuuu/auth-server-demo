package com.example.authserver.config;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * デモ用クライアント（oidc-client）の登録内容（docs/harness.md §3.1 の oauth/*・secret/*）を、実際に DB に入った形で確かめる。
 */
@SpringBootTest
class OidcClientRegistrationTest {

    @Autowired
    RegisteredClientRepository repository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    @Qualifier("clientLoader")
    ApplicationRunner clientLoader;

    @Test
    void PKCE必須でリフレッシュトークンを使い回さない() {
        RegisteredClient client = repository.findByClientId("oidc-client");

        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
    }

    @Test
    void シークレットは平文で保存しない() {
        RegisteredClient client = repository.findByClientId("oidc-client");

        assertThat(client.getClientSecret()).doesNotStartWith("{noop}").isNotEqualTo("test-only-client-secret");
        assertThat(passwordEncoder.matches("test-only-client-secret", client.getClientSecret())).isTrue();
    }

    @Test
    void 既にある古い設定のクライアントは同じidのまま上書きする() throws Exception {
        String id = repository.findByClientId("oidc-client").getId();
        repository.save(RegisteredClient.withId(id)
                .clientId("oidc-client")
                .clientSecret("{noop}old")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.com/cb")
                .scope("openid")
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .build());

        clientLoader.run(null);

        RegisteredClient client = repository.findByClientId("oidc-client");
        assertThat(client.getId()).isEqualTo(id);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
        assertThat(client.getClientSecret()).doesNotStartWith("{noop}");
        assertThat(repository.findById(UUID.randomUUID().toString())).isNull();
    }
}
