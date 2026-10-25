package com.example.authserver.data;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * ローテーションで捨てたリフレッシュトークンの保存先（表 oauth2_rotated_refresh_token。docs/harness.md §7.6）。
 *
 * <p>トークンそのものは保存しない。呼び出し側が SHA-256 のハッシュ（16進64文字）を渡す。</p>
 */
@Repository
public class RotatedRefreshTokenRepository {

    private final JdbcTemplate jdbc;

    public RotatedRefreshTokenRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * 捨てたトークンを覚える（期限切れの行はついでに消す）。期限を過ぎたトークンは使い回されても元から通らないので覚えない。
     * 同じトークンを同時に2回捨てた（同じリフレッシュトークンで同時に2本の要求が来た）ときは、先に入った行を残す。
     */
    public void record(String tokenHash, String authorizationId, Instant expiresAt, Instant now) {
        jdbc.update("DELETE FROM oauth2_rotated_refresh_token WHERE expires_at <= ?", Timestamp.from(now));
        if (expiresAt == null || expiresAt.isAfter(now)) {
            try {
                jdbc.update("INSERT INTO oauth2_rotated_refresh_token (token_hash, authorization_id, expires_at) VALUES (?, ?, ?)",
                        tokenHash, authorizationId, Timestamp.from(expiresAt != null ? expiresAt : now.plusSeconds(86400L * 365)));
            } catch (DuplicateKeyException alreadyRecorded) {
                // 同じ authorization の同じトークン＝もう覚えている。500 にしない（docs/harness.md §7.6）
            }
        }
    }

    /** 捨てたトークンなら、それを出した authorization の id。 */
    public Optional<String> findAuthorizationId(String tokenHash) {
        List<String> rows = jdbc.queryForList(
                "SELECT authorization_id FROM oauth2_rotated_refresh_token WHERE token_hash = ?", String.class, tokenHash);
        return rows.stream().findFirst();
    }

    public void deleteByAuthorizationId(String authorizationId) {
        jdbc.update("DELETE FROM oauth2_rotated_refresh_token WHERE authorization_id = ?", authorizationId);
    }
}
