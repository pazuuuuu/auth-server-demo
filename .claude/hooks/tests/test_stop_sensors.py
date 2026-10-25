"""stop_sensors.py（Stop フック）のテスト。docs/harness.md §7.1。

守ること：見張る範囲が変わったときだけ流す／落ちたら exit 2 で違反を返す／止めるのは連鎖で2回まで／
記録が失われても上限がかかる側へ倒す／止めた事象を .git/harness/events.jsonl に残す。
"""
import json
import os
import unittest

from support import RepoTestCase


class StopSensorsTest(RepoTestCase):

    def stop(self, mode="pass", active=False, session="s1"):
        event = {"session_id": session, "stop_hook_active": active, "cwd": self.root}
        return self.hook("stop_sensors.py", stdin=json.dumps(event), FAKE_MVNW_MODE=mode)

    def calls(self):
        try:
            with open(os.path.join(self.root, "mvnw-calls.log"), encoding="utf-8") as f:
                return f.read().splitlines()
        except OSError:
            return []

    def counter(self, session="s1"):
        return os.path.join(self.git_dir(), "harness-stop-blocks-" + session)

    def change_src(self, text="class A { int x; }\n"):
        self.put("src/main/java/A.java", text)

    # --- いつ流すか ---

    def test_見張る範囲に変更が無ければ流さない(self):
        self.assertEqual(self.stop("violation")[0], 0)
        self.assertEqual(self.calls(), [])

    def test_docsだけの変更では流さない(self):
        self.put("docs/harness.md", "# changed\n")
        self.assertEqual(self.stop("violation")[0], 0)
        self.assertEqual(self.calls(), [])

    def test_srcの未コミットの変更で規約テストだけを流す(self):
        self.change_src()
        self.assertEqual(self.stop("pass")[0], 0)
        self.assertEqual(len(self.calls()), 1)
        self.assertIn("test -Dtest=*RulesTest", self.calls()[0])

    def test_未追跡のsrcのファイルでも流す(self):
        self.put("src/main/java/B.java", "class B {}\n")
        self.stop("pass")
        self.assertEqual(len(self.calls()), 1)

    def test_pom_xmlの変更でも流す(self):
        self.put("pom.xml", "<project><x/></project>\n")
        self.stop("pass")
        self.assertEqual(len(self.calls()), 1)

    def test_mainに無いコミットがあれば作業ツリーがきれいでも流す(self):
        self.git("checkout", "-q", "-b", "feat/x")
        self.change_src()
        self.git("commit", "-q", "-am", "change")
        self.assertEqual(self.stop("pass")[0], 0)
        self.assertEqual(len(self.calls()), 1)

    def test_mainに無いコミットがdocsだけなら流さない(self):
        self.git("checkout", "-q", "-b", "docs/x")
        self.put("docs/harness.md", "# changed\n")
        self.git("commit", "-q", "-am", "docs")
        self.stop("pass")
        self.assertEqual(self.calls(), [])

    def test_同じ変更で一度通ったら流し直さない_変更が増えたら流す(self):
        self.change_src()
        self.stop("pass")
        self.stop("pass")
        self.assertEqual(len(self.calls()), 1)
        self.change_src("class A { int y; }\n")
        self.stop("pass")
        self.assertEqual(len(self.calls()), 2)

    def test_落ちた変更は通った印を残さず次も流す(self):
        self.change_src()
        self.stop("violation")
        self.stop("violation", session="s2")
        self.assertEqual(len(self.calls()), 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "target", "harness", "last-ok")))

    def test_gitリポジトリでなければ止めない(self):
        import shutil
        shutil.rmtree(os.path.join(self.root, ".git"))
        self.change_src()
        self.assertEqual(self.stop("violation")[0], 0)
        self.assertEqual(self.calls(), [])

    # --- 落ちたときに返すもの ---

    def test_規約違反ならexit2で違反と回数を返す(self):
        self.change_src()
        code, out, err = self.stop("violation")
        self.assertEqual(code, 2)
        self.assertIn("[log/stdout]", err)
        self.assertIn("src/main/java/A.java:3", err)
        self.assertIn("1/2", err)
        self.assertNotIn("\tat ", err)  # スタックトレースは返さない

    def test_規約テストが違反以外で落ちたらそのレポートを返す(self):
        self.change_src()
        code, _, err = self.stop("broken")
        self.assertEqual(code, 2)
        self.assertIn("違反以外の理由で落ちた", err)
        self.assertIn("baseline の書式が読めない", err)

    def test_コンパイルエラーならERROR行を返す(self):
        self.change_src()
        code, _, err = self.stop("compile")
        self.assertEqual(code, 2)
        self.assertIn("コンパイルかビルドが失敗した", err)
        self.assertIn("';' expected", err)
        self.assertNotIn("Help 1", err)

    def test_前回のレポートを今回の違反として返さない(self):
        self.change_src()
        self.stop("violation")
        code, _, err = self.stop("compile", session="s2")
        self.assertEqual(code, 2)
        self.assertNotIn("[log/stdout]", err)
        self.assertIn("コンパイルかビルドが失敗した", err)

    # --- 止めるのは2回まで ---

    def test_連鎖で止めるのは2回まで_3回目は警告だけで止めない(self):
        self.change_src()
        self.assertEqual(self.stop("violation", active=False)[0], 2)
        code, _, err = self.stop("violation", active=True)
        self.assertEqual(code, 2)
        self.assertIn("2/2", err)
        code, out, _ = self.stop("violation", active=True)
        self.assertEqual(code, 0)
        message = json.loads(out)["systemMessage"]
        self.assertIn("2 回止めても", message)
        self.assertIn("[log/stdout]", message)

    def test_新しい連鎖では回数を数え直す(self):
        self.change_src()
        self.stop("violation", active=False)
        self.stop("violation", active=True)
        self.assertEqual(self.stop("violation", active=False)[0], 2)  # stop_hook_active でない＝利用者の次の指示

    def test_緑になったら回数を消す(self):
        self.change_src()
        self.stop("violation")
        self.assertTrue(os.path.exists(self.counter()))
        self.stop("pass", active=True)
        self.assertFalse(os.path.exists(self.counter()))

    def test_回数はセッションごとに分ける(self):
        self.change_src()
        self.stop("violation", session="s1")
        self.stop("violation", active=True, session="s1")
        self.assertEqual(self.stop("violation", active=True, session="s2")[0], 2)

    def test_回数が壊れていたらあと1回で上限とみなす(self):
        self.change_src()
        self.stop("violation")
        with open(self.counter(), "w", encoding="utf-8") as f:
            f.write("壊れた")
        self.assertEqual(self.stop("violation", active=True)[0], 2)
        self.assertEqual(self.stop("violation", active=True)[0], 0)

    def test_回数が消えていたらあと1回で上限とみなす(self):
        self.change_src()
        self.stop("violation")
        os.remove(self.counter())
        self.assertEqual(self.stop("violation", active=True)[0], 2)
        self.assertEqual(self.stop("violation", active=True)[0], 0)

    def test_連鎖の途中で回数を書けなければ止めない(self):
        self.change_src()
        os.makedirs(self.counter())  # 同じ名前のディレクトリ＝ファイルとして書けない
        code, out, _ = self.stop("violation", active=True)
        self.assertEqual(code, 0)
        self.assertIn("記録できない", json.loads(out)["systemMessage"])

    def test_連鎖の最初なら回数を書けなくても1回は止める(self):
        self.change_src()
        os.makedirs(self.counter())
        self.assertEqual(self.stop("violation", active=False)[0], 2)

    # --- 記録 ---

    def test_止めたら違反とstop_blockを記録する_抑止した違反は記録しない(self):
        self.change_src()
        self.stop("violation")
        rows = self.store()
        rules = [r for r in rows if r["rule"] == "log/stdout"]
        self.assertEqual([r["fp"] for r in rules], ["fp-1"])
        self.assertEqual(rules[0]["source"], "stop")
        self.assertEqual(rules[0]["branch"], "main")
        block = [r for r in rows if r["rule"] == "harness/stop-block"]
        self.assertEqual([(b["status"], b["count"]) for b in block], [("blocked", 1)])

    def test_警告に回したらstatusはwarned_同じ違反は重ねない(self):
        self.change_src()
        self.stop("violation")
        self.stop("violation", active=True)
        self.stop("violation", active=True)
        rows = self.store()
        self.assertEqual(len([r for r in rows if r["rule"] == "log/stdout"]), 1)
        self.assertEqual([(r["status"], r["count"]) for r in rows if r["rule"] == "harness/stop-block"],
                         [("blocked", 1), ("blocked", 2), ("warned", 3)])

    def test_通ったときは何も記録しない(self):
        self.change_src()
        self.stop("pass")
        self.assertEqual(self.store(), [])


if __name__ == "__main__":
    unittest.main()
