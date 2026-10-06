package com.example.authserver.web;

import com.example.authserver.data.User;
import com.example.authserver.data.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * 既定（dev 以外）のプロファイルでは、再設定リンク（＝トークン）も利用者名もログに出さない（docs/harness.md §3.1 log/sensitive）。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class ResetLinkNotLoggedTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder encoder;

    @Test
    void 再設定リンクも利用者名もログに出さない(CapturedOutput output) throws Exception {
        users.save(new User("bob-log-check", encoder.encode("SomePassphrase-2026"), true));

        mvc.perform(post("/forgot-password").param("username", "bob-log-check").with(csrf()))
                .andExpect(redirectedUrl("/forgot-password/sent"));

        assertThat(output.getAll()).contains("no mail delivery is configured")
                .doesNotContain("reset-password?token=")
                .doesNotContain("bob-log-check");
    }
}
