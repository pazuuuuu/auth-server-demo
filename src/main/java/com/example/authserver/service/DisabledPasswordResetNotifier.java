package com.example.authserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** メール送信を設定していない環境：何も送らず、リンクも利用者名もログに出さない。 */
@Component
@Profile("!dev")
public class DisabledPasswordResetNotifier implements PasswordResetNotifier {

    private static final Logger log = LoggerFactory.getLogger(DisabledPasswordResetNotifier.class);

    @Override
    public void send(String username, String resetLink) {
        log.warn("password reset requested, but no mail delivery is configured");
    }
}
