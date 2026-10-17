package com.example.authserver.data;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** パスキーを DB に置く（docs/SLO.md §7・SLO-2）。保存した内容が欠けずに戻ること、認証で更新した署名カウンタが残ることを確かめる。 */
@SpringBootTest
class PasskeyRepositoriesTest {

    @Autowired
    UserCredentialRepository credentials;

    @Autowired
    PublicKeyCredentialUserEntityRepository userEntities;

    @Test
    void アプリはDBの実装を使う() {
        assertThat(credentials).isInstanceOf(JdbcUserCredentialRepository.class);
        assertThat(userEntities).isInstanceOf(JdbcPublicKeyCredentialUserEntityRepository.class);
    }

    @Test
    void 利用者のuser_handleを保存し名前でも引ける() {
        Bytes id = Bytes.random();
        userEntities.save(entity(id, "carol", "Carol"));

        assertThat(userEntities.findById(id).getName()).isEqualTo("carol");
        assertThat(userEntities.findByUsername("carol").getId()).isEqualTo(id);

        userEntities.save(entity(id, "carol", "Carol C."));
        assertThat(userEntities.findById(id).getDisplayName()).isEqualTo("Carol C.");

        userEntities.delete(id);
        assertThat(userEntities.findById(id)).isNull();
        assertThat(userEntities.findByUsername("carol")).isNull();
    }

    @Test
    void パスキーを欠けずに保存して読み戻せる() {
        Bytes userId = Bytes.random();
        CredentialRecord record = record(Bytes.random(), userId, 0);

        credentials.save(record);
        CredentialRecord found = credentials.findByCredentialId(record.getCredentialId());

        assertThat(found.getCredentialId()).isEqualTo(record.getCredentialId());
        assertThat(found.getUserEntityUserId()).isEqualTo(userId);
        assertThat(found.getPublicKey().getBytes()).isEqualTo(record.getPublicKey().getBytes());
        assertThat(found.getCredentialType()).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY);
        assertThat(found.getTransports()).containsExactlyInAnyOrder(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID);
        assertThat(found.isUvInitialized()).isTrue();
        assertThat(found.isBackupEligible()).isTrue();
        assertThat(found.isBackupState()).isFalse();
        assertThat(found.getAttestationObject()).isEqualTo(record.getAttestationObject());
        assertThat(found.getAttestationClientDataJSON()).isEqualTo(record.getAttestationClientDataJSON());
        assertThat(found.getCreated()).isEqualTo(record.getCreated());
        assertThat(found.getLabel()).isEqualTo("MacBook");
        assertThat(credentials.findByUserId(userId)).hasSize(1);
    }

    @Test
    void 認証で更新した署名カウンタと最終利用日時を上書きで残す() {
        Bytes credentialId = Bytes.random();
        Bytes userId = Bytes.random();
        credentials.save(record(credentialId, userId, 0));

        Instant used = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        credentials.save(ImmutableCredentialRecord.fromCredentialRecord(credentials.findByCredentialId(credentialId))
                .signatureCount(5).lastUsed(used).build());

        CredentialRecord found = credentials.findByCredentialId(credentialId);
        assertThat(found.getSignatureCount()).isEqualTo(5);
        assertThat(found.getLastUsed()).isEqualTo(used);
        assertThat(credentials.findByUserId(userId)).hasSize(1);
    }

    @Test
    void 消したパスキーは見つからない() {
        Bytes credentialId = Bytes.random();
        Bytes userId = Bytes.random();
        credentials.save(record(credentialId, userId, 0));

        credentials.delete(credentialId);

        assertThat(credentials.findByCredentialId(credentialId)).isNull();
        assertThat(credentials.findByUserId(userId)).isEmpty();
    }

    @Test
    void 他人のuser_handleのパスキーは返さない() {
        Bytes mine = Bytes.random();
        credentials.save(record(Bytes.random(), mine, 0));

        assertThat(credentials.findByUserId(Bytes.random())).isEmpty();
    }

    private static PublicKeyCredentialUserEntity entity(Bytes id, String name, String displayName) {
        return ImmutablePublicKeyCredentialUserEntity.builder().id(id).name(name).displayName(displayName).build();
    }

    private static CredentialRecord record(Bytes credentialId, Bytes userId, long signatureCount) {
        Instant created = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        return ImmutableCredentialRecord.builder()
                .credentialId(credentialId)
                .userEntityUserId(userId)
                .credentialType(PublicKeyCredentialType.PUBLIC_KEY)
                .publicKey(new ImmutablePublicKeyCose(new byte[] {1, 2, 3, 4, 5}))
                .signatureCount(signatureCount)
                .uvInitialized(true)
                .backupEligible(true)
                .backupState(false)
                .transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
                .attestationObject(new Bytes(new byte[] {9, 8, 7}))
                .attestationClientDataJSON(new Bytes(new byte[] {6, 5}))
                .created(created)
                .lastUsed(created)
                .label("MacBook")
                .build();
    }
}
