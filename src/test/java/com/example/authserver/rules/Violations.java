package com.example.authserver.rules;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * 規約センサーの違反を集めて、まとめて1回落とす（docs/harness.md §3）。
 *
 * <p>★<strong>読み手はエージェント（と人）</strong>。落ちたときのメッセージだけで直せるように、
 * 1件ごとに「どこ（file:line）」「何の規約か（ルールID）」「直し方」「根拠（docs/harness.md の節・RFC 等）」を並べる。
 * センサーは「落ちる」だけでなく「次に何をすればよいか」まで返してはじめて、ループが自分で閉じる。</p>
 *
 * <p>抑止は<strong>その行に</strong> <code>rules:allow &lt;ルールID&gt; &lt;理由&gt;</code> と書いたときだけ効く
 * （Java は <code>//</code> のコメントで）。
 * 理由の無い抑止はそれ自体を違反にする＝黙って黙らせる道を作らない。</p>
 *
 * <p>あわせて、違反と抑止を1件1行の JSON で {@code target/harness/events/rules.jsonl} に追記する
 * （docs/harness.md・webmailer のハーネス設計 §10.4 と同じ形）。Stop フックと CI がこれに出どころ・コミットを足して記録へ回す。
 * 書けなくても判定（落とす・通す）は変えない。</p>
 */
final class Violations {

    private static final Pattern ALLOW = Pattern.compile("rules:allow\\s+([\\w/.-]+)(\\s+(\\S.*))?");

    private final String sensor;
    private final List<String> items = new ArrayList<String>();
    private final List<String> events = new ArrayList<String>();
    private final List<String> hits = new ArrayList<String>();
    private final boolean record;

    static final String EVENTS = "target/harness/events/rules.jsonl";

    Violations(String sensor) {
        this(sensor, true);
    }

    /**
     * @param record false なら事象を記録しない（カナリア＝わざと違反させる見本のテスト用。記録に偽の違反を混ぜない）
     */
    Violations(String sensor, boolean record) {
        this.sensor = sensor;
        this.record = record;
    }

    /** 当たったルールID（抑止したものは含まない）。カナリアのテストが「このルールが当たったか」を見る。 */
    List<String> ruleIds() {
        return new ArrayList<String>(hits);
    }

    /**
     * 違反を1件足す。{@code rawLine}（その行の原文）に抑止があれば足さない。
     *
     * @param rawLine 抑止を探す原文の行。行が無い違反（ファイル単位など）は null
     */
    void add(Path file, int line, String rawLine, String ruleId, String what, String fix, String basis) {
        if (rawLine != null) {
            Matcher m = ALLOW.matcher(rawLine);
            while (m.find()) {
                if (m.group(1).equals(ruleId)) {
                    String reason = m.group(3) == null ? "" : m.group(3).replaceAll("(--%>|\\*/)", "").trim();
                    if (reason.isEmpty()) {
                        items.add(location(file, line) + " [rules/allow-needs-reason] " + ruleId
                                + " の抑止に理由が無い\n    直し方: `rules:allow " + ruleId + " <なぜこの行は例外か>` と理由まで書く");
                        hits.add("rules/allow-needs-reason");
                        event(file, line, rawLine, "rules/allow-needs-reason", "red", "open", ruleId + " の抑止に理由が無い");
                    } else {
                        event(file, line, rawLine, ruleId, "info", "allowed", reason);
                    }
                    return;
                }
            }
        }
        items.add(location(file, line) + " [" + ruleId + "] " + what
                + "\n    直し方: " + fix
                + "\n    根拠: " + basis);
        hits.add(ruleId);
        event(file, line, rawLine, ruleId, "red", "open", what);
    }

    /** 1件でもあれば、全件を並べて落とす。 */
    void assertNone() {
        writeEvents();
        if (items.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append(sensor).append("：規約違反 ").append(items.size()).append(" 件\n");
        for (String s : items) {
            sb.append("  - ").append(s).append('\n');
        }
        sb.append("（例外にすべき行なら、その行に `rules:allow <ルールID> <理由>` を書く。docs/harness.md §3）");
        fail(sb.toString());
    }

    private void event(Path file, int line, String rawLine, String ruleId, String severity, String outcome, String note) {
        String path = file.toString().replace('\\', '/');
        String normalized = rawLine == null ? "" : rawLine.trim().replaceAll("\\s+", " ");
        events.add("{\"source\":\"rules\",\"sensor\":" + json(sensor)
                + ",\"rule\":" + json(ruleId) + ",\"severity\":" + json(severity)
                + ",\"file\":" + json(path) + ",\"line\":" + (line > 0 ? String.valueOf(line) : "null")
                + ",\"fp\":" + json(fingerprint(ruleId + "|" + path + "|" + normalized))
                + ",\"outcome\":" + json(outcome) + ",\"note\":" + json(note) + "}");
    }

    /** 追記する。並行して走る規約テストが同じファイルへ書くので、1回の書き込みで1テスト分をまとめて出す。 */
    private void writeEvents() {
        if (!record || events.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (String e : events) {
            sb.append(e).append('\n');
        }
        events.clear();
        File out = new File(EVENTS);
        Writer w = null;
        try {
            out.getParentFile().mkdirs();
            w = new OutputStreamWriter(new FileOutputStream(out, true), "UTF-8");
            w.write(sb.toString());
        } catch (IOException e) {
            System.err.println("[harness] 事象を書けなかった（判定は変えない）: " + e);
        } finally {
            if (w != null) {
                try {
                    w.close();
                } catch (IOException ignored) {
                    // 判定に影響させない
                }
            }
        }
    }

    /** 行番号ではなく行の原文で採る＝上に行が増えても同じ違反は同じ指紋（重複を除く鍵）。 */
    static String fingerprint(String text) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest(text.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                sb.append(String.format("%02x", d[i] & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String json(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String location(Path file, int line) {
        String p = file.toString().replace('\\', '/');
        return line > 0 ? p + ":" + line : p;
    }
}
