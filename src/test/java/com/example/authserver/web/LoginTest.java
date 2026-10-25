package com.example.authserver.web;

import com.example.authserver.data.User;
import com.example.authserver.data.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * パスワードでのログインの守り。守りの分岐は「しないこと」を assert する（CLAUDE.md・docs/harness.md §5 段階2）。
 * 応答の時間差による利用者の列挙は、ここでは見ない（docs/harness.md §7.4 の残り）。
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginTest {

    private static final String PASSWORD = "DavePassphrase-2026";

    @Autowired
    MockMvc mvc;

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        users.save(new User("dave", encoder.encode(PASSWORD), true));
        users.save(new User("erin", encoder.encode(PASSWORD), false));
    }

    @Test
    void 正しい資格情報なら認証する() throws Exception {
        mvc.perform(formLogin().user("dave").password(PASSWORD))
                .andExpect(authenticated().withUsername("dave"));
    }

    @Test
    void 存在しない利用者と違うパスワードと無効な利用者は同じ応答で認証しない() throws Exception {
        String[][] attempts = {{"nobody", PASSWORD}, {"dave", PASSWORD + "x"}, {"erin", PASSWORD}};
        for (String[] attempt : attempts) {
            mvc.perform(formLogin().user(attempt[0]).password(attempt[1]))
                    .andExpect(redirectedUrl("/login?error"))
                    .andExpect(unauthenticated());
        }
    }

    @Test
    void CSRFトークンが無いログインは拒否し認証しない() throws Exception {
        mvc.perform(post("/login").param("username", "dave").param("password", PASSWORD))
                .andExpect(status().isForbidden())
                .andExpect(unauthenticated());
    }

    @Test
    void ログインの前のセッションIDを使い続けない() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String before = session.getId();

        MvcResult result = mvc.perform(post("/login").with(csrf()).session(session).param("username", "dave").param("password", PASSWORD))
                .andExpect(authenticated())
                .andReturn();

        assertThat(result.getRequest().getSession().getId()).isNotEqualTo(before);
    }
}
