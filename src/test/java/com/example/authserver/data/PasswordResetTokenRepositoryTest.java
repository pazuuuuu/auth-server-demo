package com.example.authserver.data;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 再設定トークンの1回性と期限（docs/SLO.md §7）。Controller の先頭の検証を通った後に、同時に別の要求が使った・期限が切れた場合の守り。
 */
@SpringBootTest
class PasswordResetTokenRepositoryTest {

    private static final Duration TTL = Duration.ofMinutes(15);

    @Autowired
    PasswordResetTokenRepository tokens;

    @Test
    void 一度しか消費できない() {
        Instant now = Instant.now();
        tokens.replaceForUser("a".repeat(64), "dave", now.plus(TTL), now);

        assertThat(tokens.consume("a".repeat(64), now)).isTrue();
        assertThat(tokens.consume("a".repeat(64), now)).isFalse();
        assertThat(tokens.findValidUsername("a".repeat(64), now)).isEmpty();
    }

    @Test
    void 期限切れは消費できず利用者名も返さない() {
        Instant issued = Instant.now();
        tokens.replaceForUser("b".repeat(64), "erin", issued.plus(TTL), issued);
        Instant later = issued.plus(TTL).plusSeconds(1);

        assertThat(tokens.findValidUsername("b".repeat(64), later)).isEmpty();
        assertThat(tokens.consume("b".repeat(64), later)).isFalse();
    }

    @Test
    void 新しく入れると同じ利用者の前のトークンは消える() {
        Instant now = Instant.now();
        tokens.replaceForUser("c".repeat(64), "frank", now.plus(TTL), now);
        tokens.replaceForUser("d".repeat(64), "frank", now.plus(TTL), now);

        assertThat(tokens.findValidUsername("c".repeat(64), now)).isEmpty();
        assertThat(tokens.findValidUsername("d".repeat(64), now)).contains("frank");
    }
}
