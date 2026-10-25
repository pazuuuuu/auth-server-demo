"""フックのテストの土台：一時ディレクトリに git リポジトリを作り、フックを本番と同じく別プロセスで呼ぶ。

フックは標準入力・環境変数・カレントの git リポジトリだけを見るので、外から呼んで終了コードと出力と
残ったファイルを assert する（中の関数に手を入れない＝書き換えても同じテストが効く）。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

HOOKS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 偽の mvnw：呼ばれた引数を mvnw-calls.log に足し、FAKE_MVNW_MODE に応じて surefire のレポートと事象を残す。
FAKE_MVNW = textwrap.dedent("""\
    #!/bin/sh
    echo "$*" >> mvnw-calls.log
    case "$FAKE_MVNW_MODE" in
      violation)
        mkdir -p target/surefire-reports target/harness/events
        cat > target/surefire-reports/com.example.authserver.rules.AuthRulesTest.txt <<'EOF'
    -------------------------------------------------------------------------------
    Test set: com.example.authserver.rules.AuthRulesTest
    -------------------------------------------------------------------------------
    Tests run: 1, Failures: 1, Errors: 0, Skipped: 0 <<< FAILURE!
    com.example.authserver.rules.AuthRulesTest.src_mainの規約  Time elapsed: 0.1 s  <<< FAILURE!
    org.opentest4j.AssertionFailedError:
    AuthRules：規約違反 1 件
      - src/main/java/A.java:3 [log/stdout] System.out を使わずロガーを使う
    <TAB>at org.junit.jupiter.api.AssertionUtils.fail(AssertionUtils.java:38)
    EOF
        echo '{"rule":"log/stdout","fp":"fp-1","file":"src/main/java/A.java","line":3,"outcome":"open"}' > target/harness/events/rules.jsonl
        echo '{"rule":"log/stdout","fp":"fp-2","file":"src/main/java/B.java","line":9,"outcome":"allowed"}' >> target/harness/events/rules.jsonl
        exit 1 ;;
      broken)
        mkdir -p target/surefire-reports
        printf 'Tests run: 1, Failures: 1 <<< FAILURE!\\nbaseline の書式が読めない\\n' > target/surefire-reports/com.example.authserver.rules.CanaryRulesTest.txt
        exit 1 ;;
      compile)
        echo "[ERROR] /src/main/java/A.java:[3,1] ';' expected"
        echo "[ERROR] -> [Help 1]"
        exit 1 ;;
    esac
    exit 0
    """).replace("<TAB>", "\t")


CEILING = os.path.dirname(tempfile.mkdtemp(prefix="harness-hook-ceiling-"))


def clean_env(**extra):
    """CI の GITHUB_*・手元の CLAUDE_* を持ち込まない（テストが走る場所で結果が変わらないように）。"""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GITHUB_", "HARNESS_", "CLAUDE_", "GIT_", "FAKE_MVNW_"))}
    env.update({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C.UTF-8",
                # 一時ディレクトリが別の git の作業ツリーの下にあっても、親のリポジトリを見に行かない
                "GIT_CEILING_DIRECTORIES": CEILING})
    env.update(extra)
    return env


class RepoTestCase(unittest.TestCase):
    """main に1コミットある git リポジトリ（src/・pom.xml・docs/・偽の mvnw）を毎回作り直す。"""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="harness-hook-test-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.put("pom.xml", "<project/>\n")
        self.put("src/main/java/A.java", "class A {}\n")
        self.put("docs/harness.md", "# harness\n")
        self.put(".gitignore", "target/\nmvnw-calls.log\n")
        self.put("mvnw", FAKE_MVNW)
        os.chmod(os.path.join(self.root, "mvnw"), 0o755)
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")  # init -b は git 2.28 以上が要るので使わない
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")

    def put(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def git(self, *args):
        r = subprocess.run(["git", "-C", self.root] + list(args), env=clean_env(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return r.stdout.decode("utf-8").strip()

    def git_dir(self):
        return self.git("rev-parse", "--absolute-git-dir")

    def hook(self, name, args=(), stdin="", **env):
        r = subprocess.run([sys.executable, os.path.join(HOOKS, name)] + list(args),
                           input=stdin.encode("utf-8"), cwd=self.root,
                           env=clean_env(CLAUDE_PROJECT_DIR=self.root, **env),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        return r.returncode, r.stdout.decode("utf-8"), r.stderr.decode("utf-8")

    def store(self):
        """.git/harness/events.jsonl の中身（無ければ空）。"""
        return read_jsonl(os.path.join(self.git_dir(), "harness", "events.jsonl"))


def read_jsonl(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    except OSError:
        return []
