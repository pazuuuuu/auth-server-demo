#!/usr/bin/env python3
"""Stop フック：ターンを終える前に、計算系のセンサー（コンパイル＋規約テスト）を流す。
pazuuuuu/webmailer の .claude/hooks/stop_sensors.py を移したもの（docs/harness.md §2）。

- src/・pom.xml に「未コミットの変更」か「main に無いコミット」があるときだけ動く（docs だけの変更では動かない）。
- 走らせるのは `./mvnw test -Dtest=*RulesTest`：コンパイルし、規約センサー（AuthRulesTest・CanaryRulesTest）を流す。
  全体の `./mvnw verify` は PR 前（/pre-pr）と CI で回す。
- 落ちたら exit 2 で違反の一覧を返す＝エージェントはターンを終えずにそのまま直す（ループが閉じる）。
- 同じ変更で一度通ったら、変更が増えるまで再実行しない（target/harness/last-ok に指紋）。
- ★止めるのは1回の停止の連鎖で2回まで。3回目以降は止めずに警告だけ出す（無限ループを避ける）。
  回数は .git/harness-stop-blocks-<session> に持つ（target/ は mvnw clean で消える）。
  ★上限は「記録が失われても」かかる側へ倒す：読めないときは「もう1回止めた」とみなし、
  連鎖の途中で回数を書けなかったときは止めずに警告へ回す。
- 止めた・警告したときは違反を harness_events.py stop で .git/harness/events.jsonl に残す（/pre-pr で PR 説明へ移る）。

違反の文言は surefire のレポート（UTF-8）から読む。コンソール出力はロケール次第で日本語が化けるため。
判定できないとき（mvnw が無い等）は止めない。
「設計書が先」（webmailer の design_first.py）は入れていない（docs/harness.md §6 Q3＝案A）。
"""
import glob
import hashlib
import json
import os
import subprocess
import sys

HOOKS = os.path.dirname(os.path.abspath(__file__))

WATCHED = ["src", "pom.xml"]
MAX_REPORT = 6000
MAX_BLOCKS = 2


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    root = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
    active = bool(event.get("stop_hook_active"))
    counter = counter_path(root, str(event.get("session_id") or "unknown"))
    blocks = read_blocks(counter) if active else 0

    status = git(root, ["status", "--porcelain", "--"] + WATCHED)
    if status is None:
        return 0
    if not status.strip() and not branch_changes(root):
        clear_blocks(counter)
        return 0

    fingerprint = digest(root, status)
    marker = os.path.join(root, "target", "harness", "last-ok")
    if read(marker) == fingerprint:
        clear_blocks(counter)
        return 0

    for old in (glob.glob(os.path.join(root, "target", "surefire-reports", "*RulesTest.txt"))
                + glob.glob(os.path.join(root, "target", "harness", "events", "*.jsonl"))):
        os.remove(old)
    try:
        mvnw = os.path.join(root, "mvnw")
        run = subprocess.run(
            [mvnw if os.path.exists(mvnw) else "mvn", "-q", "-B", "-ntp", "test", "-Dtest=*RulesTest",
             "-Dsurefire.failIfNoSpecifiedTests=false"],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=280)
    except (OSError, subprocess.TimeoutExpired) as e:
        sys.stderr.write("[harness] センサーを実行できなかった（止めずに続行）: {0}\n".format(e))
        return 0

    if run.returncode == 0:
        write(marker, fingerprint)
        clear_blocks(counter)
        return 0

    text = report(root, run.stdout.decode("utf-8", "replace"))
    blocks += 1
    recorded = write(counter, str(blocks))
    if blocks <= MAX_BLOCKS and (recorded or not active):
        record(root, blocks, "blocked")
        sys.stderr.write("（止めるのは {0}/{1} 回目）\n".format(blocks, MAX_BLOCKS) + text)
        return 2
    record(root, blocks, "warned")
    # 3回目以降は止めない（無限ループを避ける）。利用者に見える警告だけ出す。
    why = ("{0} 回止めても計算系センサーが緑にならなかった".format(MAX_BLOCKS) if recorded
           else "止めた回数を記録できない（{0} に書けない）".format(counter))
    print(json.dumps({"systemMessage": "[harness] 警告：" + why + "ので、止めずにターンを終える。"
                                       "違反が残っている（target/surefire-reports/*RulesTest.txt）。\n\n" + text},
                     ensure_ascii=False))
    return 0


def record(root, blocks, action):
    """止めた（blocked）・警告に回した（warned）事象を残す。失敗しても判定は変えない。"""
    try:
        subprocess.run([sys.executable, os.path.join(HOOKS, "harness_events.py"), "stop", str(blocks), action],
                       cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def report(root, console):
    lines = ["[harness] 計算系センサーが落ちた。ターンを終える前に直すこと（docs/harness.md）。", ""]
    found = False
    reports = sorted(glob.glob(os.path.join(root, "target", "surefire-reports", "*RulesTest.txt")))
    for path in reports:
        text = read(path) or ""
        start = text.find("規約違反")
        if start < 0:
            if "FAILURE" in text:
                # 規約テスト自体が違反以外の理由で落ちた（baseline の書式が壊れた等）。
                found = True
                lines.append("規約テストが違反以外の理由で落ちた（{0}）：".format(os.path.basename(path)))
                lines.extend(text.splitlines()[:30])
                lines.append("")
            continue
        found = True
        head = text.rfind("\n", 0, start) + 1
        end = text.find("\tat ", start)
        lines.append(text[head:end if end > 0 else len(text)].rstrip())
        lines.append("")
    if not found:
        # 規約テストまで届かなかった＝コンパイルエラー等。mvn の [ERROR] 行を返す。
        errors = [l for l in console.splitlines() if l.startswith("[ERROR]") and "Help 1" not in l
                  and "re-run Maven" not in l and "full stack trace" not in l and "please read" not in l]
        lines.append("コンパイルかビルドが失敗した：")
        lines.extend(errors[:40] or console.splitlines()[-40:])
        lines.append("")
        lines.append("./mvnw -q test -Dtest=*RulesTest で同じものを手元で流せる。")
    out = "\n".join(lines) + "\n"
    return out if len(out) <= MAX_REPORT else out[:MAX_REPORT] + "\n…（省略。target/surefire-reports/*RulesTest.txt を読む）\n"


def branch_changes(root):
    """main（origin/main を優先）との分岐点から HEAD までに、見張る範囲を変えたコミットがあるか。"""
    for ref in ("origin/main", "main"):
        base = git(root, ["merge-base", "HEAD", ref])
        if base and base.strip():
            names = git(root, ["diff", "--name-only", base.strip(), "HEAD", "--"] + WATCHED)
            return bool(names and names.strip())
    return False


def digest(root, status):
    h = hashlib.sha1(status.encode("utf-8"))
    h.update((git(root, ["rev-parse", "HEAD"]) or "").encode("utf-8"))
    h.update((git(root, ["diff", "HEAD", "--"] + WATCHED) or "").encode("utf-8"))
    untracked = git(root, ["ls-files", "--others", "--exclude-standard", "--"] + WATCHED) or ""
    for rel in sorted(untracked.splitlines()):
        try:
            with open(os.path.join(root, rel), "rb") as f:
                h.update(rel.encode("utf-8"))
                h.update(f.read())
        except OSError:
            pass
    return h.hexdigest()


def git(root, args):
    try:
        r = subprocess.run(["git", "-C", root] + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return None
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def counter_path(root, session):
    """止めた回数の置き場所。mvn clean で消えない .git の下（無ければ OS の一時ディレクトリ）。セッションごとに1ファイル。"""
    name = "harness-stop-blocks-" + "".join(c for c in session if c.isalnum() or c in "-_")[:80]
    git_dir = (git(root, ["rev-parse", "--absolute-git-dir"]) or "").strip()
    if git_dir:
        return os.path.join(git_dir, name)
    import tempfile
    return os.path.join(tempfile.gettempdir(), "auth-server-demo-" + name)


def read_blocks(path):
    """stop_hook_active のときだけ呼ぶ。読めない・壊れていれば MAX_BLOCKS - 1（あと1回で警告へ）。"""
    try:
        with open(path, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return MAX_BLOCKS - 1


def clear_blocks(path):
    try:
        os.remove(path)
    except OSError:
        pass


def write(path, text):
    """書けたら True。"""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except OSError:
        return False


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


if __name__ == "__main__":
    sys.exit(main())
