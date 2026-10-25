package com.example.authserver.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 認可コード＋PKCE の守りを、エンドポイントへの要求で確かめる（OidcClientRegistrationTest は設定値、こちらは振る舞い）。
 * 守りの分岐は「しないこと」を assert する（CLAUDE.md・docs/harness.md §5 段階2）。根拠は RFC 9700。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationCodeFlowTest {

    private static final String CLIENT_ID = "oidc-client";
    private static final String SECRET = "test-only-client-secret-0123456789abcdef";
    private static final String REDIRECT = "https://oidcdebugger.com/debug";
    private static final String VERIFIER = "verifier-0123456789-0123456789-0123456789-abcdef";

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper json;

    @Autowired
    JdbcTemplate jdbc;

    // --- 認可エンドポイント ---

    @Test
    void PKCEのcode_challengeが無ければ認可コードを出さない() throws Exception {
        MultiValueMap<String, String> params = redirectParams(mvc.perform(authorize(REDIRECT)).andReturn());

        assertThat(params.getFirst("error")).isEqualTo("invalid_request");
        assertThat(params).doesNotContainKey("code");
    }

    @Test
    void PKCEのplainでは認可コードを出さない() throws Exception {
        MultiValueMap<String, String> params = redirectParams(mvc.perform(authorize(REDIRECT)
                .queryParam("code_challenge", VERIFIER).queryParam("code_challenge_method", "plain")).andReturn());

        assertThat(params.getFirst("error")).isEqualTo("invalid_request");
        assertThat(params).doesNotContainKey("code");
    }

    @Test
    void 登録の無いredirect_uriへは転送しない() throws Exception {
        // RFC 9700 §4.1.3：登録した値と完全に一致するものだけ（前方一致・大文字小文字の違い・クエリの足し込みも通さない）
        for (String uri : new String[] {"https://evil.example/cb", "https://oidcdebugger.com/debug/evil",
                "https://oidcdebugger.com.evil.example/debug", "http://oidcdebugger.com/debug",
                "https://oidcdebugger.com@evil.example/debug", "https://oidcdebugger.com/debug?x=1",
                "https://oidcdebugger.com/debug/", "https://OIDCDEBUGGER.com/debug"}) {
            MvcResult result = mvc.perform(withPkce(authorize(uri))).andReturn();

            assertThat(result.getResponse().getStatus()).as(uri).isEqualTo(400);
            assertThat(result.getResponse().getHeader("Location")).as(uri).isNull();
        }
    }

    @Test
    void implicitのresponse_type_tokenではトークンを出さない() throws Exception {
        MvcResult result = mvc.perform(withPkce(get("/oauth2/authorize").with(user("carol"))
                .queryParam("response_type", "token").queryParam("client_id", CLIENT_ID).queryParam("scope", "openid")
                .queryParam("redirect_uri", REDIRECT).queryParam("state", "s"))).andReturn();

        // リダイレクトもしない（フラグメントにトークンを載せて返す経路が無い）
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(result.getResponse().getErrorMessage()).contains("unsupported_response_type");
        assertThat(result.getResponse().getHeader("Location")).isNull();
    }

    // --- トークンエンドポイント ---

    @Test
    void 正しいcode_verifierなら交換できる() throws Exception {
        JsonNode tokens = exchange(code(), VERIFIER, 200);

        assertThat(tokens.path("access_token").asText()).isNotEmpty();
        assertThat(tokens.path("refresh_token").asText()).isNotEmpty();
        assertThat(tokens.path("id_token").asText()).isNotEmpty();
    }

    @Test
    void code_verifierが無ければ交換しない() throws Exception {
        JsonNode error = exchange(code(), null, 400);

        assertThat(error.path("error").asText()).isEqualTo("invalid_grant");
        assertThat(error.has("access_token")).isFalse();
    }

    @Test
    void 違うcode_verifierでは交換しない() throws Exception {
        JsonNode error = exchange(code(), VERIFIER + "x", 400);

        assertThat(error.path("error").asText()).isEqualTo("invalid_grant");
        assertThat(error.has("access_token")).isFalse();
    }

    @Test
    void トークン要求のredirect_uriが認可要求と違えば交換しない() throws Exception {
        // RFC 6749 §4.1.3。どちらもこのクライアントに登録済みの値
        JsonNode error = body(mvc.perform(post("/oauth2/token").with(httpBasic(CLIENT_ID, SECRET))
                        .param("grant_type", "authorization_code").param("code", code())
                        .param("redirect_uri", "http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                        .param("code_verifier", VERIFIER))
                .andExpect(status().isBadRequest()).andReturn());

        assertThat(error.path("error").asText()).isEqualTo("invalid_grant");
        assertThat(error.has("access_token")).isFalse();
    }

    @Test
    void 期限切れの認可コードでは交換しない() throws Exception {
        String code = code();
        int updated = jdbc.update("UPDATE oauth2_authorization SET authorization_code_issued_at = ?, authorization_code_expires_at = ?"
                        + " WHERE authorization_code_value = ?",
                Timestamp.from(Instant.now().minusSeconds(600)), Timestamp.from(Instant.now().minusSeconds(60)), code);
        assertThat(updated).as("期限切れにした認可コード").isEqualTo(1);

        JsonNode error = exchange(code, VERIFIER, 400);

        assertThat(error.path("error").asText()).isEqualTo("invalid_grant");
        assertThat(error.has("access_token")).isFalse();
    }

    @Test
    void 認可コードは一度しか使えず二度目が来たら出したトークンも無効にする() throws Exception {
        String code = code();
        JsonNode first = exchange(code, VERIFIER, 200);

        assertThat(exchange(code, VERIFIER, 400).path("error").asText()).isEqualTo("invalid_grant");
        // RFC 6749 §4.1.2：コードが2回使われたら、そのコードで出したトークンを取り消す（コードが漏れたとみなす）。
        // 取り消しが効くのは記録を見る経路（introspection・userinfo）だけ。JWT をローカルで検証する側は exp まで受け入れる
        assertThat(introspect(first.path("access_token").asText()).path("active").asBoolean()).isFalse();
        assertThat(refresh(first.path("refresh_token").asText(), 400).path("error").asText()).isEqualTo("invalid_grant");
    }

    @Test
    void リフレッシュトークンは使い回さず使った古いトークンでは出さない() throws Exception {
        String old = exchange(code(), VERIFIER, 200).path("refresh_token").asText();

        String rotated = refresh(old, 200).path("refresh_token").asText();
        assertThat(rotated).isNotEmpty().isNotEqualTo(old);
        assertThat(refresh(rotated, 200).path("refresh_token").asText()).isNotEmpty().isNotEqualTo(rotated);

        assertThat(refresh(old, 400).path("error").asText()).isEqualTo("invalid_grant");
    }

    @Test
    void 使い回しを見つけたら今有効なトークンも失効させる() throws Exception {
        JsonNode first = exchange(code(), VERIFIER, 200);
        JsonNode second = refresh(first.path("refresh_token").asText(), 200);
        assertThat(introspect(second.path("access_token").asText()).path("active").asBoolean()).isTrue();

        // 古いトークンが来た＝どちらかが盗まれた。どちらが正しいクライアントか区別できないので丸ごと失効させる（RFC 9700 §4.14.2）
        assertThat(refresh(first.path("refresh_token").asText(), 400).path("error").asText()).isEqualTo("invalid_grant");

        assertThat(refresh(second.path("refresh_token").asText(), 400).path("error").asText()).isEqualTo("invalid_grant");
        assertThat(introspect(second.path("access_token").asText()).path("active").asBoolean()).isFalse();
        // 失効した authorization の見張りの行も残さない
        assertThat(rotatedRows(first.path("refresh_token").asText())).isZero();
    }

    @Test
    void 使い回しで失効させるのはその許可だけで他の許可は失効させない() throws Exception {
        JsonNode reused = exchange(code(), VERIFIER, 200);
        JsonNode other = exchange(code(), VERIFIER, 200);
        refresh(reused.path("refresh_token").asText(), 200);

        refresh(reused.path("refresh_token").asText(), 400);

        assertThat(introspect(other.path("access_token").asText()).path("active").asBoolean()).isTrue();
        assertThat(refresh(other.path("refresh_token").asText(), 200).path("access_token").asText()).isNotEmpty();
    }

    @Test
    void 古いトークンをintrospectionに出しただけでは失効させない() throws Exception {
        JsonNode first = exchange(code(), VERIFIER, 200);
        JsonNode second = refresh(first.path("refresh_token").asText(), 200);

        // token_type_hint なし＝トークンの種類を決めずに引く経路。グラントではないので使い回しとはみなさない
        assertThat(introspect(first.path("refresh_token").asText()).path("active").asBoolean()).isFalse();

        assertThat(refresh(second.path("refresh_token").asText(), 200).path("access_token").asText()).isNotEmpty();
    }

    @Test
    void 使い回しの見張りにはトークンそのものを置かずハッシュだけを置く() throws Exception {
        String old = exchange(code(), VERIFIER, 200).path("refresh_token").asText();
        refresh(old, 200);

        List<String> hashes = jdbc.queryForList("SELECT token_hash FROM oauth2_rotated_refresh_token", String.class);

        assertThat(hashes).contains(sha256(old)).doesNotContain(old);
    }

    @Test
    void 知らないリフレッシュトークンでは何も失効させない() throws Exception {
        JsonNode tokens = exchange(code(), VERIFIER, 200);

        assertThat(refresh("not-a-refresh-token", 400).path("error").asText()).isEqualTo("invalid_grant");

        assertThat(refresh(tokens.path("refresh_token").asText(), 200).path("access_token").asText()).isNotEmpty();
    }

    @Test
    void リフレッシュで元の許可に無いscopeを求めたら出さない() throws Exception {
        String refreshToken = exchange(code(), VERIFIER, 200).path("refresh_token").asText();

        // RFC 6749 §6：元の許可（openid だけ）より広い scope は出さない
        JsonNode error = body(mvc.perform(post("/oauth2/token").with(httpBasic(CLIENT_ID, SECRET))
                        .param("grant_type", "refresh_token").param("refresh_token", refreshToken)
                        .param("scope", "openid profile"))
                .andExpect(status().isBadRequest()).andReturn());

        assertThat(error.path("error").asText()).isEqualTo("invalid_scope");
        assertThat(error.has("access_token")).isFalse();
    }

    @Test
    void passwordグラントでは出さない() throws Exception {
        mvc.perform(post("/oauth2/token").with(httpBasic(CLIENT_ID, SECRET))
                        .param("grant_type", "password").param("username", "carol").param("password", "x"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void クライアントの認証が無いか違えば交換しない() throws Exception {
        String code = code();
        for (MockHttpServletRequestBuilder request : new MockHttpServletRequestBuilder[] {
                tokenRequest(code, VERIFIER),                                       // 認証なし
                tokenRequest(code, VERIFIER).param("client_id", CLIENT_ID),         // 公開クライアントのふり（PKCE だけ）
                tokenRequest(code, VERIFIER).with(httpBasic(CLIENT_ID, SECRET + "x"))}) { // シークレット違い
            MvcResult result = mvc.perform(request).andReturn();

            assertThat(result.getResponse().getStatus()).isIn(400, 401);
            assertThat(body(result).path("error").asText()).isIn("invalid_client", "invalid_request");
            assertThat(body(result).has("access_token")).isFalse();
        }
        // 認証に失敗した要求でコードを使い切らない（正しいクライアントはまだ交換できる）
        exchange(code, VERIFIER, 200);
    }

    // --- 補助 ---

    /** Spring Authorization Server は認可要求のパラメータをクエリ文字列からだけ読むので queryParam で渡す。 */
    private static MockHttpServletRequestBuilder authorize(String redirectUri) {
        return get("/oauth2/authorize").with(user("carol"))
                .queryParam("response_type", "code").queryParam("client_id", CLIENT_ID).queryParam("scope", "openid")
                .queryParam("redirect_uri", redirectUri).queryParam("state", "s");
    }

    private static MockHttpServletRequestBuilder withPkce(MockHttpServletRequestBuilder request) throws Exception {
        return request.queryParam("code_challenge", challenge(VERIFIER)).queryParam("code_challenge_method", "S256");
    }

    private String code() throws Exception {
        MultiValueMap<String, String> params = redirectParams(mvc.perform(withPkce(authorize(REDIRECT))).andReturn());
        assertThat(params.getFirst("code")).as("認可コード（%s）", params).isNotEmpty();
        return params.getFirst("code");
    }

    private static MultiValueMap<String, String> redirectParams(MvcResult result) {
        String location = result.getResponse().getHeader("Location");
        assertThat(location).as("status=%s error=%s", result.getResponse().getStatus(), result.getResponse().getErrorMessage()).startsWith(REDIRECT + "?");
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams();
    }

    private static MockHttpServletRequestBuilder tokenRequest(String code, String verifier) {
        MockHttpServletRequestBuilder request = post("/oauth2/token")
                .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", REDIRECT);
        return verifier == null ? request : request.param("code_verifier", verifier);
    }

    private JsonNode exchange(String code, String verifier, int expectedStatus) throws Exception {
        return body(mvc.perform(tokenRequest(code, verifier).with(httpBasic(CLIENT_ID, SECRET)))
                .andExpect(status().is(expectedStatus)).andReturn());
    }

    private JsonNode refresh(String refreshToken, int expectedStatus) throws Exception {
        return body(mvc.perform(post("/oauth2/token").with(httpBasic(CLIENT_ID, SECRET))
                        .param("grant_type", "refresh_token").param("refresh_token", refreshToken))
                .andExpect(status().is(expectedStatus)).andReturn());
    }

    private JsonNode introspect(String token) throws Exception {
        return body(mvc.perform(post("/oauth2/introspect").with(httpBasic(CLIENT_ID, SECRET)).param("token", token))
                .andExpect(status().isOk()).andReturn());
    }

    private JsonNode body(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private int rotatedRows(String refreshToken) throws Exception {
        return jdbc.queryForObject("SELECT COUNT(*) FROM oauth2_rotated_refresh_token WHERE token_hash = ?",
                Integer.class, sha256(refreshToken));
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
