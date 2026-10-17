package com.example.authserver.service;

import com.example.authserver.data.PasswordResetTokenRepository;
import com.example.authserver.data.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class PasswordResetTokenService {

    static final Duration TOKEN_TTL = Duration.ofMinutes(15);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetNotifier notifier;
    private final String baseUrl;

    public PasswordResetTokenService(UserRepository userRepository, PasswordResetTokenRepository tokenRepository,
                                     PasswordEncoder passwordEncoder, PasswordResetNotifier notifier,
                                     @Value("${app.base-url}") String baseUrl) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.notifier = notifier;
        this.baseUrl = baseUrl;
    }

    @Transactional
    public String createToken(String username) {
        if (!userRepository.existsById(username)) {
            // Security: Do not reveal if user exists
            return null;
        }
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        Instant now = Instant.now();
        // DB にはハッシュだけを置く（docs/SLO.md §7）
        tokenRepository.replaceForUser(hash(token), username, now.plus(TOKEN_TTL), now);

        // 届け方は PasswordResetNotifier に任せる（dev はログで模擬・それ以外は送らない）。ここではトークンをログに出さない
        notifier.send(username, baseUrl + "/reset-password?token=" + token);

        return token;
    }

    public boolean validateToken(String token) {
        return getUsername(token) != null;
    }

    public String getUsername(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        return tokenRepository.findValidUsername(hash(token), Instant.now()).orElse(null);
    }

    /** トークンを使ってパスワードを変える。使えた（期限内で、まだ使われていなかった）ときだけ true。 */
    @Transactional
    public boolean updatePassword(String token, String newPassword) {
        String username = getUsername(token);
        if (username == null || !tokenRepository.consume(hash(token), Instant.now())) {
            return false;
        }
        return userRepository.findById(username).map(user -> {
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            return true;
        }).orElse(false);
    }

    static String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
