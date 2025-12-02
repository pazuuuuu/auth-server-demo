package com.example.authserver.service;

import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class PasswordValidationService {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 64; // NIST recommends at least 64
    private static final List<String> BLOCKLIST = Arrays.asList(
            "password", "123456", "12345678", "qwerty", "admin", "secret", "pass1234"
    );

    public ValidationResult validate(String password, String confirmPassword, String username) {
        if (password == null || password.isEmpty()) {
            return new ValidationResult(false, "Password is required.");
        }

        if (!password.equals(confirmPassword)) {
            return new ValidationResult(false, "Passwords do not match.");
        }

        if (password.length() < MIN_LENGTH) {
            return new ValidationResult(false, "Password must be at least " + MIN_LENGTH + " characters long.");
        }

        if (password.length() > MAX_LENGTH) {
            return new ValidationResult(false, "Password is too long.");
        }

        // NIST: No composition rules (e.g. "must contain special chars") enforced.
        // Just check against blocklist.

        if (BLOCKLIST.contains(password.toLowerCase())) {
            return new ValidationResult(false, "This password is too common and cannot be used.");
        }

        if (username != null && password.toLowerCase().contains(username.toLowerCase())) {
             return new ValidationResult(false, "Password cannot contain your username.");
        }

        return new ValidationResult(true, null);
    }

    public record ValidationResult(boolean isValid, String errorMessage) {}
}
