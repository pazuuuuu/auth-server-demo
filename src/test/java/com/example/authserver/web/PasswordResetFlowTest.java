package com.example.authserver.web;

import com.example.authserver.data.User;
import com.example.authserver.data.UserRepository;
import com.example.authserver.service.PasswordResetNotifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * パスワード再設定の守り。守りの分岐は「しないこと」を assert する（CLAUDE.md・docs/harness.md §3.2 review/test-negative）。
 */
@SpringBootTest
@AutoConfigureMockMvc
class PasswordResetFlowTest {

    private static final String OLD = "OldPassphrase-2026";
    private static final String NEW = "NewPassphrase-2026";

    @Autowired
    MockMvc mvc;

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JdbcTemplate jdbc;

    @MockitoBean
    PasswordResetNotifier notifier;

    @BeforeEach
    void setUp() {
        users.save(new User("alice", encoder.encode(OLD), true));
        reset(notifier);
    }

    @Test
    void CSRFトークンが無い再設定要求は拒否し送らない() throws Exception {
        mvc.perform(post("/forgot-password").param("username", "alice"))
                .andExpect(status().isForbidden());

        verify(notifier, never()).send(anyString(), anyString());
    }

    @Test
    void 存在しない利用者には送らないが応答は同じ() throws Exception {
        mvc.perform(post("/forgot-password").param("username", "nobody").with(csrf()))
                .andExpect(redirectedUrl("/forgot-password/sent"));

        verify(notifier, never()).send(anyString(), anyString());
    }

    @Test
    void トークンは一度しか使えない() throws Exception {
        String token = requestToken();

        mvc.perform(resetWith(token, NEW)).andExpect(redirectedUrl("/reset-password/success"));
        assertThat(encoder.matches(NEW, password())).isTrue();

        mvc.perform(resetWith(token, "ThirdPassphrase-2026")).andExpect(redirectedUrl("/login?error=invalid_token"));
        assertThat(encoder.matches(NEW, password())).isTrue();
    }

    @Test
    void CSRFトークンが無い再設定は拒否しパスワードを変えない() throws Exception {
        String token = requestToken();

        mvc.perform(post("/reset-password").param("token", token)
                        .param("password", NEW).param("confirmPassword", NEW))
                .andExpect(status().isForbidden());

        assertThat(encoder.matches(OLD, password())).isTrue();
    }

    @Test
    void 知らないトークンでは変えない() throws Exception {
        mvc.perform(resetWith("not-a-token", NEW)).andExpect(redirectedUrl("/login?error=invalid_token"));

        assertThat(encoder.matches(OLD, password())).isTrue();
    }

    @Test
    void 期限切れのトークンでは変えない() throws Exception {
        String token = "expired-token-for-test";
        jdbc.update("INSERT INTO password_reset_token (token_hash, username, expires_at) VALUES (?, ?, ?)",
                sha256(token), "alice", Timestamp.from(Instant.now().minusSeconds(60)));

        mvc.perform(resetWith(token, NEW)).andExpect(redirectedUrl("/login?error=invalid_token"));

        assertThat(encoder.matches(OLD, password())).isTrue();
    }

    @Test
    void DBにはトークンそのものを置かずハッシュだけを置く() throws Exception {
        String token = requestToken();

        List<String> hashes = jdbc.queryForList(
                "SELECT token_hash FROM password_reset_token WHERE username = ?", String.class, "alice");

        assertThat(hashes).containsExactly(sha256(token)).doesNotContain(token);
    }

    @Test
    void 新しいリンクを送ると前のリンクでは変えない() throws Exception {
        mvc.perform(post("/forgot-password").param("username", "alice").with(csrf()));
        mvc.perform(post("/forgot-password").param("username", "alice").with(csrf()));
        ArgumentCaptor<String> link = ArgumentCaptor.forClass(String.class);
        verify(notifier, times(2)).send(eq("alice"), link.capture());
        String first = tokenOf(link.getAllValues().get(0));
        String second = tokenOf(link.getAllValues().get(1));

        mvc.perform(resetWith(first, NEW)).andExpect(redirectedUrl("/login?error=invalid_token"));
        assertThat(encoder.matches(OLD, password())).isTrue();

        mvc.perform(resetWith(second, NEW)).andExpect(redirectedUrl("/reset-password/success"));
        assertThat(encoder.matches(NEW, password())).isTrue();
    }

    private static String tokenOf(String link) {
        return link.substring(link.indexOf("token=") + "token=".length());
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private String requestToken() throws Exception {
        mvc.perform(post("/forgot-password").param("username", "alice").with(csrf()))
                .andExpect(redirectedUrl("/forgot-password/sent"));
        ArgumentCaptor<String> link = ArgumentCaptor.forClass(String.class);
        verify(notifier).send(eq("alice"), link.capture());
        assertThat(link.getValue()).startsWith("http://localhost:8080/reset-password?token=");
        return link.getValue().substring(link.getValue().indexOf("token=") + "token=".length());
    }

    private org.springframework.test.web.servlet.RequestBuilder resetWith(String token, String password) {
        return post("/reset-password").with(csrf()).param("token", token)
                .param("password", password).param("confirmPassword", password);
    }

    private String password() {
        return users.findById("alice").orElseThrow().getPassword();
    }
}
