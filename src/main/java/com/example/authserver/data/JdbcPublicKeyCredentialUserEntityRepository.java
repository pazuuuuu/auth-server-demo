package com.example.authserver.data;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;

import java.util.List;

/**
 * パスキーの利用者（WebAuthn の user handle と利用者名の対応。表 user_entities）。
 * 以前はメモリ上で、再起動すると user handle が作り直され、登録済みのパスキーと結び付かなくなった（docs/SLO.md §7）。
 *
 * <p>Spring Security 6.4 には JDBC 版が無いので自作した。表の形は 6.5 の {@code JdbcPublicKeyCredentialUserEntityRepository} に合わせてある
 * （Spring Boot 3.5 に上げたら標準のものに置き換えられる）。</p>
 */
public class JdbcPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

    private static final String COLUMNS = "id, name, display_name";

    private static final RowMapper<PublicKeyCredentialUserEntity> MAPPER = (rs, n) -> ImmutablePublicKeyCredentialUserEntity.builder()
            .id(Bytes.fromBase64(rs.getString("id")))
            .name(rs.getString("name"))
            .displayName(rs.getString("display_name"))
            .build();

    private final JdbcTemplate jdbc;

    public JdbcPublicKeyCredentialUserEntityRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public PublicKeyCredentialUserEntity findById(Bytes id) {
        return first(jdbc.query("SELECT " + COLUMNS + " FROM user_entities WHERE id = ?", MAPPER, id.toBase64UrlString()));
    }

    @Override
    public PublicKeyCredentialUserEntity findByUsername(String username) {
        return first(jdbc.query("SELECT " + COLUMNS + " FROM user_entities WHERE name = ?", MAPPER, username));
    }

    @Override
    public void save(PublicKeyCredentialUserEntity entity) {
        String id = entity.getId().toBase64UrlString();
        int updated = jdbc.update("UPDATE user_entities SET name = ?, display_name = ? WHERE id = ?",
                entity.getName(), entity.getDisplayName(), id);
        if (updated == 0) {
            jdbc.update("INSERT INTO user_entities (" + COLUMNS + ") VALUES (?, ?, ?)",
                    id, entity.getName(), entity.getDisplayName());
        }
    }

    @Override
    public void delete(Bytes id) {
        jdbc.update("DELETE FROM user_entities WHERE id = ?", id.toBase64UrlString());
    }

    private static <T> T first(List<T> rows) {
        return rows.isEmpty() ? null : rows.get(0);
    }
}
