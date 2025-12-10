package com.example.authserver.service;

import com.example.authserver.data.UserRepository;
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
    private final Map<String, TokenInfo> tokenStore = new ConcurrentHashMap<>();

    public PasswordResetTokenService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public String createToken(String username) {
        if (!userRepository.existsById(username)) {
            // Security: Do not reveal if user exists
            return null;
        }
        String token = UUID.randomUUID().toString();
        tokenStore.put(token, new TokenInfo(username, LocalDateTime.now().plusMinutes(15)));

        // Simulation: Log the email
        System.out.println("--------------------------------------------------");
        System.out.println("[Email Simulation] Password Reset Request");
        System.out.println("To: " + username); // Using username as email for this demo
        System.out.println("Link: http://localhost:8080/reset-password?token=" + token);
        System.out.println("--------------------------------------------------");

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
