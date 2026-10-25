package com.example.authserver.data;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/** 捨てたリフレッシュトークンの見張りの行（docs/harness.md §7.6）。 */
@SpringBootTest
class RotatedRefreshTokenRepositoryTest {

    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");

    @Autowired
    RotatedRefreshTokenRepository repository;

    @Autowired
    JdbcTemplate jdbc;

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM oauth2_rotated_refresh_token");
    }

    @Test
    void 同じトークンを二度覚えようとしても失敗する文を出さず先の行を残す() {
        repository.record("h1", "auth-1", NOW.plusSeconds(60), NOW);

        assertThatCode(() -> repository.record("h1", "auth-2", NOW.plusSeconds(60), NOW)).doesNotThrowAnyException();

        assertThat(repository.findAuthorizationId("h1")).contains("auth-1");
    }

    @Test
    void 期限を過ぎたトークンは覚えず期限切れの行は消す() {
        jdbc.update("INSERT INTO oauth2_rotated_refresh_token (token_hash, authorization_id, expires_at) VALUES ('old', 'auth-0', ?)",
                java.sql.Timestamp.from(NOW.minusSeconds(1)));

        repository.record("h2", "auth-1", NOW.minusSeconds(60), NOW);
        repository.purgeExpired(NOW);

        assertThat(repository.findAuthorizationId("h2")).isEmpty();
        assertThat(repository.findAuthorizationId("old")).isEmpty();
    }

    @Test
    void authorizationを消すとその行だけ消える() {
        repository.record("h3", "auth-1", NOW.plusSeconds(60), NOW);
        repository.record("h4", "auth-2", NOW.plusSeconds(60), NOW);

        repository.deleteByAuthorizationId("auth-1");

        assertThat(repository.findAuthorizationId("h3")).isEmpty();
        assertThat(repository.findAuthorizationId("h4")).contains("auth-2");
    }
}
