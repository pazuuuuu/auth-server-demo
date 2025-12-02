package com.example.authserver.web;

import com.example.authserver.service.PasswordResetTokenService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ForgotPasswordController {

    private final PasswordResetTokenService passwordResetTokenService;

    public ForgotPasswordController(PasswordResetTokenService passwordResetTokenService) {
        this.passwordResetTokenService = passwordResetTokenService;
    }

    @GetMapping("/forgot-password")
    public String forgotPasswordForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String processForgotPassword(@RequestParam("username") String username) {
        passwordResetTokenService.createToken(username);
        // Always redirect to success page to prevent user enumeration
        return "redirect:/forgot-password/sent";
    }

    @GetMapping("/forgot-password/sent")
    public String forgotPasswordSent() {
        return "forgot-password-sent";
    }
}
