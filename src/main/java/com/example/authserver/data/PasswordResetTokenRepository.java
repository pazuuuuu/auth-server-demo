package com.example.authserver.data;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * パスワード再設定トークンの保存先（表 password_reset_token）。以前はメモリ上で、再起動すると送ったリンクが使えなくなった（docs/SLO.md §7）。
 *
 * <p>トークンそのものは保存しない。呼び出し側が SHA-256 のハッシュ（16進64文字）を渡す＝DB が漏れても再設定リンクは作れない。</p>
 */
@Repository
public class PasswordResetTokenRepository {

    private final JdbcTemplate jdbc;

    public PasswordResetTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** 利用者ごとに有効なリンクは1本だけにする（前のリンクと期限切れの行を消してから入れる）。 */
    @Transactional
    public void replaceForUser(String tokenHash, String username, Instant expiresAt, Instant now) {
        jdbc.update("DELETE FROM password_reset_token WHERE username = ? OR expires_at <= ?", username, Timestamp.from(now));
        jdbc.update("INSERT INTO password_reset_token (token_hash, username, expires_at) VALUES (?, ?, ?)",
                tokenHash, username, Timestamp.from(expiresAt));
    }

    /** 期限内のトークンの利用者名。無い・期限切れなら空。 */
    public Optional<String> findValidUsername(String tokenHash, Instant now) {
        List<String> rows = jdbc.queryForList(
                "SELECT username FROM password_reset_token WHERE token_hash = ? AND expires_at > ?",
                String.class, tokenHash, Timestamp.from(now));
        return rows.stream().findFirst();
    }

    /** 期限内のトークンを消す。消せたら true＝この呼び出しが使った（同時に2回使われても片方だけ true になる）。 */
    public boolean consume(String tokenHash, Instant now) {
        return jdbc.update("DELETE FROM password_reset_token WHERE token_hash = ? AND expires_at > ?",
                tokenHash, Timestamp.from(now)) == 1;
    }
}
