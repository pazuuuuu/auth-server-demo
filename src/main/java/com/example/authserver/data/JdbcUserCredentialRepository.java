package com.example.authserver.data;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 登録済みのパスキー（公開鍵・署名カウンタ等。表 user_credentials）。
 * 以前はメモリ上で、再起動すると登録したパスキーが消えた（docs/SLO.md §7・SLO-2）。
 *
 * <p>Spring Security 6.4 には JDBC 版が無いので自作した。表の形は 6.5 の {@code JdbcUserCredentialRepository} に合わせてある。
 * 認証のたびに署名カウンタと最終利用日時が {@link #save} で更新される（カウンタの巻き戻り＝複製の検知に使われる）。</p>
 */
public class JdbcUserCredentialRepository implements UserCredentialRepository {

    private static final String COLUMNS = "credential_id, user_entity_user_id, public_key, signature_count, uv_initialized,"
            + " backup_eligible, authenticator_transports, public_key_credential_type, backup_state,"
            + " attestation_object, attestation_client_data_json, created, last_used, label";

    private static final RowMapper<CredentialRecord> MAPPER = JdbcUserCredentialRepository::map;

    private final JdbcTemplate jdbc;

    public JdbcUserCredentialRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(CredentialRecord record) {
        String id = record.getCredentialId().toBase64UrlString();
        int updated = jdbc.update("UPDATE user_credentials SET user_entity_user_id = ?, public_key = ?, signature_count = ?,"
                        + " uv_initialized = ?, backup_eligible = ?, authenticator_transports = ?, public_key_credential_type = ?,"
                        + " backup_state = ?, attestation_object = ?, attestation_client_data_json = ?, created = ?, last_used = ?,"
                        + " label = ? WHERE credential_id = ?",
                userId(record), record.getPublicKey().getBytes(), record.getSignatureCount(), record.isUvInitialized(),
                record.isBackupEligible(), transports(record.getTransports()), type(record.getCredentialType()),
                record.isBackupState(), bytes(record.getAttestationObject()), bytes(record.getAttestationClientDataJSON()),
                timestamp(record.getCreated()), timestamp(record.getLastUsed()), record.getLabel(), id);
        if (updated == 0) {
            jdbc.update("INSERT INTO user_credentials (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    id, userId(record), record.getPublicKey().getBytes(), record.getSignatureCount(), record.isUvInitialized(),
                    record.isBackupEligible(), transports(record.getTransports()), type(record.getCredentialType()),
                    record.isBackupState(), bytes(record.getAttestationObject()), bytes(record.getAttestationClientDataJSON()),
                    timestamp(record.getCreated()), timestamp(record.getLastUsed()), record.getLabel());
        }
    }

    @Override
    public CredentialRecord findByCredentialId(Bytes credentialId) {
        List<CredentialRecord> rows = jdbc.query("SELECT " + COLUMNS + " FROM user_credentials WHERE credential_id = ?",
                MAPPER, credentialId.toBase64UrlString());
        return rows.isEmpty() ? null : rows.get(0);
    }

    @Override
    public List<CredentialRecord> findByUserId(Bytes userId) {
        return jdbc.query("SELECT " + COLUMNS + " FROM user_credentials WHERE user_entity_user_id = ?",
                MAPPER, userId.toBase64UrlString());
    }

    @Override
    public void delete(Bytes credentialId) {
        jdbc.update("DELETE FROM user_credentials WHERE credential_id = ?", credentialId.toBase64UrlString());
    }

    private static CredentialRecord map(ResultSet rs, int rowNum) throws SQLException {
        ImmutableCredentialRecord.ImmutableCredentialRecordBuilder b = ImmutableCredentialRecord.builder()
                .credentialId(Bytes.fromBase64(rs.getString("credential_id")))
                .userEntityUserId(Bytes.fromBase64(rs.getString("user_entity_user_id")))
                .publicKey(new ImmutablePublicKeyCose(rs.getBytes("public_key")))
                .signatureCount(rs.getLong("signature_count"))
                .uvInitialized(rs.getBoolean("uv_initialized"))
                .backupEligible(rs.getBoolean("backup_eligible"))
                .transports(parseTransports(rs.getString("authenticator_transports")))
                .backupState(rs.getBoolean("backup_state"))
                .label(rs.getString("label"));
        String type = rs.getString("public_key_credential_type");
        if (type != null) {
            b.credentialType(PublicKeyCredentialType.valueOf(type));
        }
        byte[] attestation = rs.getBytes("attestation_object");
        if (attestation != null) {
            b.attestationObject(new Bytes(attestation));
        }
        byte[] clientData = rs.getBytes("attestation_client_data_json");
        if (clientData != null) {
            b.attestationClientDataJSON(new Bytes(clientData));
        }
        Timestamp created = rs.getTimestamp("created");
        if (created != null) {
            b.created(created.toInstant());
        }
        Timestamp lastUsed = rs.getTimestamp("last_used");
        if (lastUsed != null) {
            b.lastUsed(lastUsed.toInstant());
        }
        return b.build();
    }

    private static String userId(CredentialRecord record) {
        return record.getUserEntityUserId().toBase64UrlString();
    }

    private static String transports(Set<AuthenticatorTransport> transports) {
        if (transports == null || transports.isEmpty()) {
            return null;
        }
        return transports.stream().map(AuthenticatorTransport::getValue).collect(Collectors.joining(","));
    }

    private static Set<AuthenticatorTransport> parseTransports(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty())
                .map(AuthenticatorTransport::valueOf).collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static String type(PublicKeyCredentialType type) {
        return type == null ? null : type.getValue();
    }

    private static byte[] bytes(Bytes value) {
        return value == null ? null : value.getBytes();
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }
}
