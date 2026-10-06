package com.example.authserver.rules;

import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 認証・認可の規約（計算系センサー）。設計と各ルールの根拠は docs/harness.md §3.1。
 *
 * <p>字面で判定する。1ファイル分の行を受け取って {@link Violations} に積むだけにしてあるので、
 * 本物のツリー（{@code AuthRulesTest}）にも、わざと違反させた見本（{@code CanaryRulesTest}）にも同じものを当てられる。
 * ルールを書き換えて事実上無効にしても、カナリアが落ちて気づける（webmailer のハーネス設計 §10.7）。</p>
 */
final class AuthRules {

    private AuthRules() {
    }

    private static final String DOC = "docs/harness.md §3.1";

    private static final Pattern NOOP = Pattern.compile("\\{noop\\}");
    private static final Pattern SECRET_CALL = Pattern.compile(
            "\\b(clientSecret|encode|password|secret)\\s*\\(\\s*\"[^\"]+\"");
    private static final Pattern SECRET_ASSIGN = Pattern.compile(
            "(?i)\\b(password|passwd|secret|client_?secret)\\s*=\\s*\"[^\"]+\"");
    private static final Pattern STDOUT = Pattern.compile("\\bSystem\\.(out|err)\\.");
    private static final Pattern LOG_CALL = Pattern.compile(
            "\\b(log|logger|LOG|LOGGER)\\.(trace|debug|info|warn|error)\\s*\\(");
    private static final Pattern SENSITIVE_IDENT = Pattern.compile(
            "(?i)\\b\\w*(token|password|secret|link|credential)\\w*\\b");
    private static final Pattern CLIENT_BUILD = Pattern.compile("RegisteredClient\\.(withId|from)\\s*\\(");
    private static final Pattern REDIRECT = Pattern.compile(
            "\\b(redirectUri|postLogoutRedirectUri)\\s*\\(\\s*\"([^\"]*)\"");
    private static final Pattern GRANT = Pattern.compile(
            "AuthorizationGrantType\\.(IMPLICIT|PASSWORD)\\b|new\\s+AuthorizationGrantType\\s*\\(\\s*\"(implicit|password)\"");
    private static final Pattern CSRF_OFF = Pattern.compile(
            "csrf\\s*\\(\\s*\\)\\s*\\.\\s*disable\\s*\\(|csrf\\s*\\(\\s*AbstractHttpConfigurer\\s*::\\s*disable"
                    + "|csrf\\s*\\(\\s*\\w+\\s*->\\s*\\w+\\s*\\.\\s*disable\\s*\\(|ignoringRequestMatchers\\s*\\(");
    private static final Pattern IMPORT = Pattern.compile("^import\\s+com\\.example\\.authserver\\.(\\w+)\\.");
    private static final Pattern DDL = Pattern.compile("^spring\\.jpa\\.hibernate\\.ddl-auto\\s*=\\s*(update|create|create-drop)\\s*$");
    private static final Pattern SHOW_SQL = Pattern.compile("^spring\\.jpa\\.show-sql\\s*=\\s*true\\s*$");
    private static final Pattern LOG_LEVEL = Pattern.compile("(?i)^logging\\.level\\.[^=]*=\\s*(debug|trace)\\s*$");
    private static final Pattern PROP_SECRET = Pattern.compile("(?i)^([^=#]*(password|secret)[^=]*)=(.*)$");

    /** src/main/java の1ファイル。{@code layer} は com.example.authserver の直下のパッケージ名（ルート直下なら ""）。 */
    static void checkJava(Path file, List<String> lines, String layer, Violations v) {
        boolean buildsClient = false;
        int firstClientLine = 0;
        String firstClientRaw = null;
        boolean pkce = false;
        boolean rotation = false;
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            String code = stripLineComment(raw);
            String t = code.trim();
            if (t.startsWith("*") || t.startsWith("/*")) {
                continue;
            }
            int n = i + 1;
            if (NOOP.matcher(code).find()) {
                v.add(file, n, raw, "secret/noop-encoder", "`{noop}`＝平文のまま保存・照合している",
                        "PasswordEncoder（DelegatingPasswordEncoder）で encode した値を保存する", DOC);
            }
            if (SECRET_CALL.matcher(code).find() || SECRET_ASSIGN.matcher(code).find()) {
                v.add(file, n, raw, "secret/hardcoded", "パスワード・シークレットを src/main に直書きしている",
                        "環境変数（${...}）から読む。public リポジトリなので書いた時点で漏えい", DOC);
            }
            if (STDOUT.matcher(code).find()) {
                v.add(file, n, raw, "log/stdout", "System.out／System.err を使っている",
                        "SLF4J のロガー（LoggerFactory.getLogger）を使う", DOC);
            }
            if (LOG_CALL.matcher(code).find()) {
                String args = stripStrings(code);
                Matcher m = SENSITIVE_IDENT.matcher(args.substring(firstLogParen(args)));
                if (m.find()) {
                    v.add(file, n, raw, "log/sensitive", "ログにトークン・パスワード・リンク等を渡している（" + m.group() + "）",
                            "値そのものは出さない（件数・有無・ハッシュの先頭など判別に要る最小限にする）。OWASP ASVS V7", DOC);
                }
            }
            if (CLIENT_BUILD.matcher(code).find() && !buildsClient) {
                buildsClient = true;
                firstClientLine = n;
                firstClientRaw = raw;
            }
            if (code.contains("requireProofKey(true)")) {
                pkce = true;
            }
            if (code.contains("reuseRefreshTokens(false)")) {
                rotation = true;
            }
            Matcher r = REDIRECT.matcher(code);
            while (r.find()) {
                String uri = r.group(2);
                if (!allowedRedirect(uri)) {
                    v.add(file, n, raw, "oauth/redirect-uri-https", r.group(1) + " が https でも loopback でもない（" + uri + "）",
                            "https:// か http://127.0.0.1 / http://[::1] だけにする。localhost とワイルドカードは不可（RFC 8252 §7.3・RFC 9700 §4.1）", DOC);
                }
            }
            if (GRANT.matcher(code).find()) {
                v.add(file, n, raw, "oauth/implicit-password-grant", "implicit／password の grant を使っている",
                        "認可コード＋PKCE を使う（RFC 9700 §2.1.2・§2.4）", DOC);
            }
            if (CSRF_OFF.matcher(code).find()) {
                v.add(file, n, raw, "web/csrf-disable", "CSRF を無効化／一部の経路を除外している",
                        "フォームは th:action で送れば CSRF トークンが自動で入る。どうしても除外するなら理由を rules:allow に書く", DOC);
            }
            Matcher im = IMPORT.matcher(t);
            if (im.find()) {
                String to = im.group(1);
                if (("data".equals(layer) && ("web".equals(to) || "service".equals(to)))
                        || ("service".equals(layer) && "web".equals(to))) {
                    v.add(file, n, raw, "arch/layer", layer + " が " + to + " に依存している",
                            "web → service → data の向きにする（下の層は上の層を知らない）", DOC);
                }
            }
        }
        if (buildsClient && !pkce) {
            v.add(file, firstClientLine, firstClientRaw, "oauth/pkce-required", "RegisteredClient で PKCE を必須にしていない",
                    "ClientSettings.builder().requireProofKey(true)（機密クライアントも。RFC 9700 §2.1.1・OAuth 2.1）", DOC);
        }
        if (buildsClient && !rotation) {
            v.add(file, firstClientLine, firstClientRaw, "oauth/refresh-rotation", "リフレッシュトークンを使い回す設定（既定）のまま",
                    "TokenSettings.builder().reuseRefreshTokens(false)（漏えいの検知・RFC 9700 §4.14）", DOC);
        }
    }

    /** src/main/resources の .properties。{@code defaultProfile} は application.properties（プロファイル無し）のとき true。 */
    static void checkProperties(Path file, List<String> lines, boolean defaultProfile, Violations v) {
        for (int i = 0; i < lines.size(); i++) {
            String raw = lines.get(i);
            String t = raw.trim();
            if (t.isEmpty() || t.startsWith("#")) {
                continue;
            }
            int n = i + 1;
            Matcher s = PROP_SECRET.matcher(t);
            if (s.find()) {
                String value = s.group(3).trim();
                if (!value.isEmpty() && !(value.startsWith("${") && value.endsWith("}"))) {
                    v.add(file, n, raw, "secret/hardcoded", "パスワード・シークレットを設定ファイルに直書きしている",
                            "${環境変数} で受け取る（.env.example に名前だけ書く）", DOC);
                }
            }
            if (!defaultProfile) {
                continue;
            }
            if (DDL.matcher(t).find() || SHOW_SQL.matcher(t).find() || LOG_LEVEL.matcher(t).find()) {
                v.add(file, n, raw, "config/prod-defaults", "既定のプロファイルに開発向けの設定がある",
                        "ddl-auto は validate／none、show-sql と DEBUG は application-dev.properties へ", DOC);
            }
        }
    }

    static boolean allowedRedirect(String uri) {
        if (uri.contains("*")) {
            return false;
        }
        return uri.startsWith("https://") || uri.startsWith("http://127.0.0.1") || uri.startsWith("http://[::1]");
    }

    /** 行末の // コメントを落とす（文字列の中の // は残す）。 */
    static String stripLineComment(String line) {
        boolean inString = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\\' && inString) {
                i++;
            } else if (c == '"') {
                inString = !inString;
            } else if (!inString && c == '/' && i + 1 < line.length() && line.charAt(i + 1) == '/') {
                return line.substring(0, i);
            }
        }
        return line;
    }

    /** 文字列リテラルの中身を空にする（ログの文言に「token」と書いただけでは当てない）。 */
    static String stripStrings(String line) {
        return line.replaceAll("\"(\\\\.|[^\"\\\\])*\"", "\"\"");
    }

    private static int firstLogParen(String code) {
        Matcher m = LOG_CALL.matcher(code);
        return m.find() ? m.end() : 0;
    }
}
