"""harness_events.py（事象の口）のテスト。docs/harness.md §2・§7.1。

守ること：CI の結果を毎回1件残し、main への push の失敗は main-red／Stop・pre-pr は同じブランチ・同じ出どころで
同じ指紋を重ねない／reviewer は周回ごとに id を分ける／PR 説明の隠しブロックは "-->" で壊れない。
"""
import json
import os
import unittest

from support import RepoTestCase, read_jsonl


class HarnessEventsTest(RepoTestCase):

    def events(self, *args, **env):
        return self.hook("harness_events.py", args, **env)

    def target_events(self, *rows):
        self.put("target/harness/events/rules.jsonl", "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))

    def ci_rows(self):
        return read_jsonl(os.path.join(self.root, "target", "harness", "events", "ci.jsonl"))

    def report(self, *rows):
        body = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
        return self.put("target/harness/review/report.md", "# 報告\n\n本文\n\n```jsonl\n" + body + "```\n")

    def pr_block(self, *args):
        code, out, _ = self.events("pr-block", *args)
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual((lines[0], lines[-1]), ("<!-- harness-events", "-->"))
        return lines[1:-1], [json.loads(l) for l in lines[1:-1]]

    # --- ci ---

    def test_ciは違反とCIの結果を書く(self):
        self.target_events({"rule": "log/stdout", "fp": "fp-1", "outcome": "open"})
        code, _, _ = self.events("ci", "--status", "success", GITHUB_EVENT_NAME="pull_request",
                                 GITHUB_HEAD_REF="feat/x", HARNESS_HEAD_SHA="0123456789abcdef")
        self.assertEqual(code, 0)
        rows = self.ci_rows()
        self.assertEqual([r["rule"] for r in rows], ["log/stdout", "ci/result"])
        self.assertTrue(all(r["source"] == "ci" and r["branch"] == "feat/x" and r["commit"] == "0123456" for r in rows))
        self.assertEqual((rows[1]["status"], rows[1]["severity"], rows[1]["note"]), ("success", "info", None))

    def test_mainへのpushの失敗はmain_red(self):
        self.events("ci", "--status", "failure", GITHUB_EVENT_NAME="push", GITHUB_REF_NAME="main")
        result = self.ci_rows()[-1]
        self.assertEqual((result["severity"], result["note"]), ("red", "main-red"))

    def test_mainでないブランチへのpushの失敗はmain_redにしない(self):
        self.events("ci", "--status", "failure", GITHUB_EVENT_NAME="push", GITHUB_REF_NAME="feat/x")
        result = self.ci_rows()[-1]
        self.assertEqual((result["severity"], result["note"]), ("red", None))

    def test_PRの失敗はmain_redにしない(self):
        self.events("ci", "--status", "failure", GITHUB_EVENT_NAME="pull_request", GITHUB_HEAD_REF="main")
        self.assertIsNone(self.ci_rows()[-1]["note"])

    def test_mainへのpushの成功と取り消しはmain_redにしない(self):
        for status in ("success", "cancelled"):
            self.events("ci", "--status", status, GITHUB_EVENT_NAME="push", GITHUB_REF_NAME="main")
            result = self.ci_rows()[-1]
            self.assertEqual((result["severity"], result["note"]), ("info", None), status)

    def test_PR番号はイベントのファイルから読む(self):
        path = self.put("event.json", json.dumps({"pull_request": {"number": 42}}))
        self.events("ci", "--status", "success", GITHUB_EVENT_PATH=path)
        self.assertEqual(self.ci_rows()[-1]["pr"], 42)

    def test_PR番号はrefからも読む(self):
        self.events("ci", "--status", "success", GITHUB_REF="refs/pull/7/merge")
        self.assertEqual(self.ci_rows()[-1]["pr"], 7)

    def test_ciは前の回のファイルに足さず作り直す(self):
        self.events("ci", "--status", "failure")
        self.events("ci", "--status", "success")
        self.assertEqual([r["status"] for r in self.ci_rows()], ["success"])

    def test_ciは手元のgitに記録を書かない(self):
        self.target_events({"rule": "log/stdout", "fp": "fp-1", "outcome": "open"})
        self.events("ci", "--status", "success")
        self.assertEqual(self.store(), [])

    # --- stop・pre-pr ---

    def test_stopは同じブランチで同じ指紋を重ねない_ブランチが違えば残す(self):
        self.target_events({"rule": "log/stdout", "fp": "fp-1", "outcome": "open"})
        self.events("stop", "1", "blocked")
        self.events("stop", "2", "blocked")
        self.git("checkout", "-q", "-b", "feat/x")
        self.events("stop", "1", "blocked")
        rules = [r for r in self.store() if r["rule"] == "log/stdout"]
        self.assertEqual([r["branch"] for r in rules], ["main", "feat/x"])

    def test_stopは抑止した違反を記録しない(self):
        self.target_events({"rule": "log/stdout", "fp": "fp-2", "outcome": "allowed"})
        self.events("stop", "1", "blocked")
        self.assertEqual([r["rule"] for r in self.store()], ["harness/stop-block"])

    def test_pre_prは出どころが違うのでstopと同じ指紋でも残す(self):
        self.target_events({"rule": "log/stdout", "fp": "fp-1", "outcome": "open"})
        self.events("stop", "1", "blocked")
        _, out, _ = self.events("pre-pr")
        self.assertIn("pre-pr の事象 1 件を", out)
        _, out, _ = self.events("pre-pr")
        self.assertIn("pre-pr の事象 0 件を", out)
        self.assertEqual(sorted(r["source"] for r in self.store() if r["rule"] == "log/stdout"), ["pre-pr", "stop"])

    # --- reviewer ---

    def test_reviewerは周回ごとにidを分け_outcomeはopen_指紋は捨てる(self):
        report = self.report({"id": "R1", "rule": "review/reset-token", "fp": "x", "outcome": "fixed"})
        self.assertEqual(self.events("reviewer", report)[0], 0)
        self.assertEqual(self.events("reviewer", report)[0], 0)
        rows = [r for r in self.store() if r["source"] == "reviewer"]
        self.assertEqual([(r["id"], r["item"], r["round"], r["outcome"]) for r in rows],
                         [("r1-R1", "R1", 1, "open"), ("r2-R1", "R1", 2, "open")])
        self.assertTrue(all("fp" not in r for r in rows))

    def test_reviewerの周回はブランチごとに数える(self):
        report = self.report({"id": "R1"})
        self.events("reviewer", report)
        self.git("checkout", "-q", "-b", "feat/x")
        self.events("reviewer", report)
        self.assertEqual(self.store()[-1]["id"], "r1-R1")

    def test_jsonlブロックの無い報告は失敗にして何も書かない(self):
        report = self.put("target/harness/review/report.md", "# 報告\n\n指摘なし\n")
        code, _, err = self.events("reviewer", report)
        self.assertEqual(code, 1)
        self.assertIn("jsonl", err)
        self.assertEqual(self.store(), [])

    def test_読めない行は飛ばして残りを記録する(self):
        report = self.put("target/harness/review/report.md", '```jsonl\n{"id":"R1"}\nnot json\n{"id":"Y1"}\n```\n')
        self.assertEqual(self.events("reviewer", report)[0], 0)
        self.assertEqual([r["id"] for r in self.store()], ["r1-R1", "r1-Y1"])

    # --- pr-block ---

    def test_pr_blockは前の周回をfixed_最後の周回をopen_指定があればそれ(self):
        self.events("reviewer", self.report({"id": "R1"}, {"id": "Y1"}))
        self.events("reviewer", self.report({"id": "R1"}, {"id": "Y1"}, {"id": "Y2"}))
        _, rows = self.pr_block("--outcome", "R1=fixed,Y2=wontfix")
        self.assertEqual({r["id"]: r["outcome"] for r in rows},
                         {"r1-R1": "fixed", "r1-Y1": "fixed", "r2-R1": "fixed", "r2-Y1": "open", "r2-Y2": "wontfix"})

    def test_pr_blockの周回なしの指定は最後の周回だけを指す(self):
        self.events("reviewer", self.report({"id": "Y1"}))
        self.events("reviewer", self.report({"id": "Y1"}))
        _, rows = self.pr_block("--outcome", "Y1=wontfix")
        self.assertEqual({r["id"]: r["outcome"] for r in rows}, {"r1-Y1": "fixed", "r2-Y1": "wontfix"})

    def test_pr_blockの周回つきの指定は前の周回も指せる(self):
        self.events("reviewer", self.report({"id": "Y1"}))
        self.events("reviewer", self.report({"id": "Y1"}))
        _, rows = self.pr_block("--outcome", "r1-Y1=wontfix")
        self.assertEqual({r["id"]: r["outcome"] for r in rows}, {"r1-Y1": "wontfix", "r2-Y1": "open"})

    def test_pr_blockはStopの違反をfixedにし_stop_blockはopenのまま(self):
        self.target_events({"rule": "log/stdout", "fp": "fp-1", "outcome": "open"})
        self.events("stop", "1", "blocked")
        _, rows = self.pr_block()
        self.assertEqual({r["rule"]: r["outcome"] for r in rows}, {"log/stdout": "fixed", "harness/stop-block": "open"})

    def test_pr_blockはこのブランチの事象だけを出す(self):
        self.events("reviewer", self.report({"id": "R1"}))
        self.git("checkout", "-q", "-b", "feat/x")
        _, rows = self.pr_block()
        self.assertEqual(rows, [])

    def test_pr_blockは値に閉じ記号があっても隠しブロックを壊さない(self):
        self.events("reviewer", self.report({"id": "R1", "note": "a --> b"}))
        lines, rows = self.pr_block()
        self.assertTrue(all("-->" not in l for l in lines))
        self.assertEqual(rows[0]["note"], "a --> b")

    # --- 使い方 ---

    def test_知らないモードは使い方を出してexit2(self):
        code, _, err = self.events("unknown")
        self.assertEqual(code, 2)
        self.assertIn("harness_events.py ci", err)


if __name__ == "__main__":
    unittest.main()
