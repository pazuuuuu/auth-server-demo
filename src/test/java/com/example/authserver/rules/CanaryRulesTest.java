package com.example.authserver.rules;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * カナリア：各ルールに「必ず当たるべき見本」と「当たってはいけない見本」を当てる（webmailer のハーネス設計 §10.7）。
 * ルールを書き換えて事実上無効にしても、ここが落ちて気づける。名前を *RulesTest にして Stop フックでも流す。
 * 見本の違反は記録しない（{@code new Violations(..., false)}）。
 */
class CanaryRulesTest {

    private static final Path JAVA_FILE = Paths.get("src/main/java/com/example/authserver/config/Canary.java");

    static Stream<Arguments> 当たるべきJava() {
        return Stream.of(
                Arguments.of("secret/noop-encoder", "", ".clientSecret(\"{noop}secret\")"),
                Arguments.of("secret/hardcoded", "", ".clientSecret(\"plain\")"),
                Arguments.of("secret/hardcoded", "", "new User(\"u\", passwordEncoder.encode(\"password\"), true);"),
                Arguments.of("secret/hardcoded", "", "String password = \"hunter2\";"),
                Arguments.of("log/stdout", "", "System.out.println(\"x\");"),
                Arguments.of("log/stdout", "", "System.err.println(e);"),
                Arguments.of("log/sensitive", "", "log.info(\"reset {}\", resetLink);"),
                Arguments.of("log/sensitive", "", "logger.debug(\"t=\" + token);"),
                Arguments.of("oauth/pkce-required", "", "RegisteredClient.withId(id).clientId(\"c\")"),
                Arguments.of("oauth/refresh-rotation", "", "RegisteredClient.withId(id).clientId(\"c\")"),
                Arguments.of("oauth/redirect-uri-https", "", ".redirectUri(\"http://localhost:8080/cb\")"),
                Arguments.of("oauth/redirect-uri-https", "", ".redirectUri(\"https://*.example.com/cb\")"),
                Arguments.of("oauth/implicit-password-grant", "", ".authorizationGrantType(AuthorizationGrantType.IMPLICIT)"),
                Arguments.of("oauth/implicit-password-grant", "", ".authorizationGrantType(new AuthorizationGrantType(\"password\"))"),
                Arguments.of("web/csrf-disable", "", "http.csrf(AbstractHttpConfigurer::disable);"),
                Arguments.of("web/csrf-disable", "", "http.csrf(c -> c.disable());"),
                Arguments.of("web/csrf-disable", "", ".csrf(csrf -> csrf.ignoringRequestMatchers(\"/x/**\"))"),
                Arguments.of("arch/layer", "data", "import com.example.authserver.web.LoginController;"),
                Arguments.of("arch/layer", "service", "import com.example.authserver.web.LoginController;"),
                Arguments.of("rules/allow-needs-reason", "", "System.out.println(\"x\"); // rules:allow log/stdout"));
    }

    @ParameterizedTest(name = "{0} は {2} に当たる")
    @MethodSource("当たるべきJava")
    void Javaの違反見本に当たる(String rule, String layer, String line) {
        assertThat(java(layer, line)).contains(rule);
    }

    static Stream<Arguments> 当たってはいけないJava() {
        return Stream.of(
                Arguments.of("", ".clientSecret(passwordEncoder.encode(clientSecret))"),
                Arguments.of("", "public static final String ACR_PASSWORD = \"urn:oasis:names:tc:SAML:2.0:ac:classes:Password\";"),
                Arguments.of("", "log.info(\"password reset requested\");"),
                Arguments.of("", "log.debug(\"refresh TTL {}\", timeToLive);"),
                Arguments.of("", ".redirectUri(\"http://127.0.0.1:8080/login/oauth2/code/c\")"),
                Arguments.of("", ".redirectUri(\"https://oidcdebugger.com/debug\")"),
                Arguments.of("", "// System.out.println(\"commented out\");"),
                Arguments.of("", " * System.out in javadoc {noop}"),
                Arguments.of("", "System.out.println(\"x\"); // rules:allow log/stdout カナリアの見本"),
                Arguments.of("web", "import com.example.authserver.service.PasswordResetTokenService;"),
                Arguments.of("service", "import com.example.authserver.data.UserRepository;"));
    }

    @ParameterizedTest(name = "{1} には当たらない")
    @MethodSource("当たってはいけないJava")
    void Javaの正しい見本には当たらない(String layer, String line) {
        assertThat(java(layer, line)).isEmpty();
    }

    @ParameterizedTest(name = "PKCE とローテーションを設定すれば当たらない")
    @MethodSource("設定済みのクライアント")
    void 設定済みのクライアントには当たらない(List<String> lines) {
        Violations v = new Violations("canary", false);
        AuthRules.checkJava(JAVA_FILE, lines, "config", v);
        assertThat(v.ruleIds()).doesNotContain("oauth/pkce-required", "oauth/refresh-rotation");
    }

    static Stream<Arguments> 設定済みのクライアント() {
        return Stream.of(Arguments.of(Arrays.asList(
                "RegisteredClient.withId(id)",
                "  .clientSettings(ClientSettings.builder().requireProofKey(true).build())",
                "  .tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build())")));
    }

    static Stream<Arguments> 設定の見本() {
        return Stream.of(
                Arguments.of(true, "spring.jpa.hibernate.ddl-auto=update", "config/prod-defaults"),
                Arguments.of(true, "spring.jpa.show-sql=true", "config/prod-defaults"),
                Arguments.of(true, "logging.level.org.springframework.security=DEBUG", "config/prod-defaults"),
                Arguments.of(true, "spring.datasource.password=hunter2", "secret/hardcoded"),
                Arguments.of(false, "app.oidc-client.secret=plain", "secret/hardcoded"),
                Arguments.of(true, "spring.jpa.hibernate.ddl-auto=validate", null),
                Arguments.of(true, "spring.datasource.password=${DB_PASSWORD}", null),
                Arguments.of(false, "logging.level.org.springframework.security=DEBUG", null));
    }

    @ParameterizedTest(name = "{1} → {2}")
    @MethodSource("設定の見本")
    void 設定の見本(boolean defaultProfile, String line, String rule) {
        Violations v = new Violations("canary", false);
        AuthRules.checkProperties(Paths.get("src/main/resources/application.properties"), Arrays.asList(line), defaultProfile, v);
        if (rule == null) {
            assertThat(v.ruleIds()).isEmpty();
        } else {
            assertThat(v.ruleIds()).contains(rule);
        }
    }

    private static List<String> java(String layer, String line) {
        Violations v = new Violations("canary", false);
        AuthRules.checkJava(JAVA_FILE, Arrays.asList(line), layer, v);
        return v.ruleIds();
    }
}
