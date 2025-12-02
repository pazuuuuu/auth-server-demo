package com.example.authserver.web;

import com.example.authserver.service.PasswordResetTokenService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ResetPasswordController {

    private final PasswordResetTokenService passwordResetTokenService;
    private final com.example.authserver.service.PasswordValidationService passwordValidationService;

    public ResetPasswordController(PasswordResetTokenService passwordResetTokenService,
                                   com.example.authserver.service.PasswordValidationService passwordValidationService) {
        this.passwordResetTokenService = passwordResetTokenService;
        this.passwordValidationService = passwordValidationService;
    }

    @GetMapping("/reset-password")
    public String resetPasswordForm(@RequestParam("token") String token, Model model) {
        if (!passwordResetTokenService.validateToken(token)) {
            return "redirect:/login?error=invalid_token";
        }
        model.addAttribute("token", token);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String processResetPassword(@RequestParam("token") String token, 
                                     @RequestParam("password") String password,
                                     @RequestParam("confirmPassword") String confirmPassword,
                                     Model model) {
        if (!passwordResetTokenService.validateToken(token)) {
            return "redirect:/login?error=invalid_token";
        }

        // Retrieve username associated with token for validation
        String username = passwordResetTokenService.getUsername(token);
        
        var validationResult = passwordValidationService.validate(password, confirmPassword, username);
        if (!validationResult.isValid()) {
            model.addAttribute("token", token);
            model.addAttribute("error", validationResult.errorMessage());
            return "reset-password";
        }

        passwordResetTokenService.updatePassword(token, password);
        return "redirect:/reset-password/success";
    }

    @GetMapping("/reset-password/success")
    public String resetPasswordSuccess() {
        return "reset-password-success";
    }
}
