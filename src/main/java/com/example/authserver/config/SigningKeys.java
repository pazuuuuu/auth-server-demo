package com.example.authserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ID トークン・アクセストークンの署名鍵（docs/SLO.md §7・SLO-5b）。
 *
 * <p>以前は起動ごとに RSA 鍵を作り直していたため、再起動すると発行済みの ID トークンを RP が検証できなかった。
 * いまは環境変数の PEM から読み、{@code kid} は鍵の SHA-256 サムプリント（RFC 7638）にする＝同じ鍵なら再起動しても {@code kid} が変わらない。</p>
 *
 * <ul>
 *   <li>{@code current}：署名に使う鍵（秘密鍵つき）。JWKS には公開鍵だけが出る</li>
 *   <li>{@code previous}：ローテーション中の旧鍵（公開鍵だけ）。JWKS に並べ、旧鍵で署名済みのトークンを検証できるようにする</li>
 * </ul>
 */
public final class SigningKeys {

    static final int MIN_RSA_BITS = 2048;

    private static final Pattern PEM = Pattern.compile(
            "-----BEGIN ([A-Z ]+)-----([A-Za-z0-9+/=\\s]+)-----END \\1-----");

    private final RSAKey current;
    private final List<RSAKey> previous;

    private SigningKeys(RSAKey current, List<RSAKey> previous) {
        this.current = current;
        this.previous = List.copyOf(previous);
    }

    /**
     * @param signingKeyPem      PKCS#8 の RSA 秘密鍵（{@code BEGIN PRIVATE KEY}）。空なら {@code allowEphemeral} のときだけ鍵を作る
     * @param previousPublicPems 旧鍵の公開鍵（{@code BEGIN PUBLIC KEY}）を0個以上。空でよい
     * @param allowEphemeral     鍵が無いとき起動ごとの鍵で動かしてよいか（dev・テストだけ true）
     */
    public static SigningKeys load(String signingKeyPem, String previousPublicPems, boolean allowEphemeral) {
        RSAKey current;
        if (signingKeyPem == null || signingKeyPem.isBlank()) {
            if (!allowEphemeral) {
                throw new IllegalStateException("JWT_SIGNING_KEY must be set to a PKCS#8 RSA private key (PEM, at least "
                        + MIN_RSA_BITS + " bits). See .env.example");
            }
            current = generate();
        } else {
            List<byte[]> blocks = pemBlocks(signingKeyPem, "PRIVATE KEY");
            if (blocks.size() != 1) {
                throw new IllegalStateException("JWT_SIGNING_KEY must contain exactly one PKCS#8 private key (BEGIN PRIVATE KEY)");
            }
            current = fromPrivateKey(blocks.get(0));
        }
        List<RSAKey> previous = new ArrayList<>();
        if (previousPublicPems != null && !previousPublicPems.isBlank()) {
            for (byte[] der : pemBlocks(previousPublicPems, "PUBLIC KEY")) {
                RSAKey key = fromPublicKey(der);
                if (!key.getKeyID().equals(current.getKeyID())) {
                    previous.add(key);
                }
            }
        }
        return new SigningKeys(current, previous);
    }

    /** 署名に使う鍵だけの集合（エンコーダに渡す。旧鍵で署名しないように分ける）。 */
    public JWKSet signingSet() {
        return new JWKSet(current);
    }

    /** JWKS に出す集合（今の鍵と旧鍵）。秘密鍵は {@code /oauth2/jwks} では公開鍵だけに変換される。 */
    public JWKSet publishedSet() {
        List<JWK> keys = new ArrayList<>();
        keys.add(current);
        keys.addAll(previous);
        return new JWKSet(keys);
    }

    public String currentKeyId() {
        return current.getKeyID();
    }

    private static RSAKey fromPrivateKey(byte[] der) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            if (!(factory.generatePrivate(new PKCS8EncodedKeySpec(der)) instanceof RSAPrivateCrtKey priv)) {
                throw new IllegalStateException("JWT_SIGNING_KEY must be an RSA private key with CRT parameters");
            }
            RSAPublicKey pub = (RSAPublicKey) factory.generatePublic(
                    new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
            requireStrength(pub);
            return new RSAKey.Builder(pub).privateKey(priv).keyIDFromThumbprint().build();
        } catch (GeneralSecurityException | JOSEException | ClassCastException ex) {
            throw new IllegalStateException("JWT_SIGNING_KEY is not a valid PKCS#8 RSA private key", ex);
        }
    }

    private static RSAKey fromPublicKey(byte[] der) {
        try {
            RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
            requireStrength(pub);
            return new RSAKey.Builder(pub).keyIDFromThumbprint().build();
        } catch (GeneralSecurityException | JOSEException | ClassCastException ex) {
            throw new IllegalStateException("JWT_PREVIOUS_PUBLIC_KEYS contains an invalid RSA public key", ex);
        }
    }

    private static RSAKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(MIN_RSA_BITS);
            KeyPair pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey(pair.getPrivate()).keyIDFromThumbprint().build();
        } catch (GeneralSecurityException | JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void requireStrength(RSAPublicKey key) {
        if (key.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new IllegalStateException("RSA signing keys must be at least " + MIN_RSA_BITS + " bits");
        }
    }

    /** 環境変数に1行で入れられるよう、文字どおりの {@code \n} も改行として読む。 */
    static List<byte[]> pemBlocks(String text, String type) {
        String normalized = text.replace("\\n", "\n");
        Matcher m = PEM.matcher(normalized);
        List<byte[]> blocks = new ArrayList<>();
        while (m.find()) {
            if (!type.equals(m.group(1))) {
                throw new IllegalStateException("expected PEM type " + type + " but found " + m.group(1));
            }
            blocks.add(Base64.getMimeDecoder().decode(m.group(2)));
        }
        if (blocks.isEmpty()) {
            throw new IllegalStateException("no PEM block of type " + type + " found");
        }
        return blocks;
    }
}
