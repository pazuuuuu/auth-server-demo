package com.example.authserver.web;

import com.example.authserver.service.PasswordResetTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/** 検証は通ったが、使う直前に期限が切れた・別の要求が先に使った場合、成功の画面を出さない（docs/SLO.md §7）。 */
@SpringBootTest
@AutoConfigureMockMvc
class ResetConsumeRaceTest {

    @Autowired
    MockMvc mvc;

    @MockitoBean
    PasswordResetTokenService tokens;

    @Test
    void 使えなかったときは成功の画面に進まない() throws Exception {
        when(tokens.validateToken(anyString())).thenReturn(true);
        when(tokens.getUsername(anyString())).thenReturn("grace");
        when(tokens.updatePassword(anyString(), anyString())).thenReturn(false);

        mvc.perform(post("/reset-password").with(csrf()).param("token", "t")
                        .param("password", "Passphrase-2026-x").param("confirmPassword", "Passphrase-2026-x"))
                .andExpect(redirectedUrl("/login?error=invalid_token"));
    }
}
