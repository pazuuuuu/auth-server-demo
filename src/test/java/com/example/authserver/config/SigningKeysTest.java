package com.example.authserver.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 署名鍵の読み込み（docs/SLO.md §7・SLO-5b）。再起動しても同じ鍵・同じ kid になること、弱い鍵や鍵なしでは起動しないことを確かめる。
 */
class SigningKeysTest {

    @Test
    void 同じPEMなら再起動してもkidが変わらない() throws Exception {
        String pem = privatePem(generate(2048));

        String first = SigningKeys.load(pem, "", false).currentKeyId();
        String second = SigningKeys.load(pem, "", false).currentKeyId();

        assertThat(first).isNotBlank().isEqualTo(second);
    }

    @Test
    void 署名には今の鍵だけを使い旧鍵は公開鍵としてJWKSに並べる() throws Exception {
        KeyPair current = generate(2048);
        KeyPair old = generate(2048);

        SigningKeys keys = SigningKeys.load(privatePem(current), publicPem(old), false);

        JWKSet signing = keys.signingSet();
        assertThat(signing.getKeys()).hasSize(1);
        assertThat(signing.getKeys().get(0).isPrivate()).isTrue();
        assertThat(signing.getKeys().get(0).getKeyID()).isEqualTo(keys.currentKeyId());

        JWKSet published = keys.publishedSet().toPublicJWKSet();
        assertThat(published.getKeys()).hasSize(2).noneMatch(JWK::isPrivate);
        assertThat(published.getKeys()).extracting(JWK::getKeyID).contains(keys.currentKeyId());
    }

    @Test
    void 今の鍵と同じ公開鍵を旧鍵に入れても重複させない() throws Exception {
        KeyPair current = generate(2048);

        SigningKeys keys = SigningKeys.load(privatePem(current), publicPem(current), false);

        assertThat(keys.publishedSet().getKeys()).hasSize(1);
    }

    @Test
    void 環境変数に1行で入れた改行も読める() throws Exception {
        String pem = privatePem(generate(2048));
        String oneLine = pem.replace("\n", "\\n");

        assertThat(SigningKeys.load(oneLine, "", false).currentKeyId())
                .isEqualTo(SigningKeys.load(pem, "", false).currentKeyId());
    }

    @Test
    void 鍵が無ければ本番では起動しない() {
        assertThatThrownBy(() -> SigningKeys.load("", "", false)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeys.load(null, null, false)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void 開発用に許したときだけ起動ごとの鍵で動く() {
        SigningKeys a = SigningKeys.load("", "", true);
        SigningKeys b = SigningKeys.load("", "", true);

        assertThat(a.currentKeyId()).isNotEqualTo(b.currentKeyId());
    }

    @Test
    void 弱い鍵や種類違いのPEMでは起動しない() throws Exception {
        KeyPair weak = generate(1024);
        KeyPair ok = generate(2048);

        assertThatThrownBy(() -> SigningKeys.load(privatePem(weak), "", false)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeys.load(privatePem(ok), publicPem(weak), false)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeys.load(publicPem(ok), "", false)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeys.load(privatePem(ok) + privatePem(ok), "", false)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SigningKeys.load("not a pem", "", false)).isInstanceOf(IllegalStateException.class);
    }

    private static KeyPair generate(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static String privatePem(KeyPair pair) {
        return pem("PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    private static String publicPem(KeyPair pair) {
        return pem("PUBLIC KEY", pair.getPublic().getEncoded());
    }

    private static String pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }
}
