package com.example.authserver.service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;

@Service
public class PasswordResetTokenService {

    private final InMemoryUserDetailsManager userDetailsManager;
    private final Map<String, TokenInfo> tokenStore = new ConcurrentHashMap<>();

    public PasswordResetTokenService(InMemoryUserDetailsManager userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }

    public String createToken(String username) {
        if (!userDetailsManager.userExists(username)) {
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
            UserDetails user = userDetailsManager.loadUserByUsername(info.username);
            
            // In a real app, we would use a PasswordEncoder. 
            // Since we used User.withDefaultPasswordEncoder() (which uses {noop} or similar),
            // we need to be careful. For this demo, we'll recreate the user with the new password.
            // InMemoryUserDetailsManager.updatePassword requires the old password, which we don't have.
            // So we use updateUser instead.
            
            UserDetails newUser = User.withDefaultPasswordEncoder()
                    .username(user.getUsername())
                    .password(newPassword)
                    .authorities(user.getAuthorities())
                    .build();
            
            userDetailsManager.updateUser(newUser);
            tokenStore.remove(token);
        }
    }

    private record TokenInfo(String username, LocalDateTime expiryDate) {}
}
