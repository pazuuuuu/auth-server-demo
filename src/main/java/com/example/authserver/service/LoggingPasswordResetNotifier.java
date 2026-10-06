package com.example.authserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** 開発用：メールの代わりにリンクをログへ出す。{@code dev} プロファイルでしか有効にならない。 */
@Component
@Profile("dev")
public class LoggingPasswordResetNotifier implements PasswordResetNotifier {

    private static final Logger log = LoggerFactory.getLogger(LoggingPasswordResetNotifier.class);

    @Override
    public void send(String username, String resetLink) {
        log.info("[dev mail] password reset for {}: {}", username, resetLink); // rules:allow log/sensitive dev プロファイル限定のメール送信の模擬（本番では Bean が作られない）
    }
}
