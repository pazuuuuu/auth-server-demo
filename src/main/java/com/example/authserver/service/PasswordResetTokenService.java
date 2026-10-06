package com.example.authserver.service;

import com.example.authserver.data.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PasswordResetTokenService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetNotifier notifier;
    private final String baseUrl;
    private final Map<String, TokenInfo> tokenStore = new ConcurrentHashMap<>();

    public PasswordResetTokenService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                                     PasswordResetNotifier notifier, @Value("${app.base-url}") String baseUrl) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.notifier = notifier;
        this.baseUrl = baseUrl;
    }

    public String createToken(String username) {
        if (!userRepository.existsById(username)) {
            // Security: Do not reveal if user exists
            return null;
        }
        String token = UUID.randomUUID().toString();
        tokenStore.put(token, new TokenInfo(username, LocalDateTime.now().plusMinutes(15)));

        // 届け方は PasswordResetNotifier に任せる（dev はログで模擬・それ以外は送らない）。ここではトークンをログに出さない
        notifier.send(username, baseUrl + "/reset-password?token=" + token);

        return token;
    }

    public boolean validateToken(String token) {
        TokenInfo info = tokenStore.get(token);
        if (info == null) {
            return false;
        }
        if (info.expiryDate.isBefore(LocalDateTime.now())) {
            tokenStore.remove(token);
            return false;
        }
        return true;
    }

    public String getUsername(String token) {
        TokenInfo info = tokenStore.get(token);
        return info != null ? info.username : null;
    }

    public void updatePassword(String token, String newPassword) {
        TokenInfo info = tokenStore.get(token);
        if (info != null && validateToken(token)) {
            userRepository.findById(info.username).ifPresent(user -> {
                user.setPassword(passwordEncoder.encode(newPassword));
                userRepository.save(user);
            });
            tokenStore.remove(token);
        }
    }

    private record TokenInfo(String username, LocalDateTime expiryDate) {
    }
}
