package com.example.authserver.rules;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/**
 * 認証・認可の規約（docs/harness.md §3.1）を src/main に当てる。違反は file:line・ルールID・直し方・根拠つきで落ちる。
 * 例外はその行の {@code rules:allow <ルールID> <理由>} だけ（理由なしは違反）。
 */
class AuthRulesTest {

    private static final Path JAVA = Paths.get("src/main/java");
    private static final Path RESOURCES = Paths.get("src/main/resources");
    private static final Path ROOT_PACKAGE = Paths.get("src/main/java/com/example/authserver");

    @Test
    void javaのソースが認証認可の規約を守る() throws IOException {
        Violations v = new Violations("AuthRulesTest");
        for (Path file : files(JAVA, ".java")) {
            AuthRules.checkJava(file, read(file), layerOf(file), v);
        }
        v.assertNone();
    }

    @Test
    void 設定ファイルが認証認可の規約を守る() throws IOException {
        Violations v = new Violations("AuthRulesTest");
        for (Path file : files(RESOURCES, "")) {
            AuthRules.checkResourceName(file, v);
        }
        for (Path file : files(RESOURCES, ".properties")) {
            AuthRules.checkProperties(file, read(file), AuthRules.strictProfile(file.getFileName().toString()), v);
        }
        v.assertNone();
    }

    static String layerOf(Path file) {
        Path rel = ROOT_PACKAGE.relativize(file);
        return rel.getNameCount() > 1 ? rel.getName(0).toString() : "";
    }

    private static List<Path> files(Path dir, String suffix) throws IOException {
        try (Stream<Path> s = Files.walk(dir)) {
            return s.filter(Files::isRegularFile).filter(p -> p.toString().endsWith(suffix)).sorted().collect(Collectors.toList());
        }
    }

    private static List<String> read(Path file) throws IOException {
        return Files.readAllLines(file, StandardCharsets.UTF_8);
    }
}
