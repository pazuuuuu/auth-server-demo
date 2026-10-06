---
name: pre-pr
description: auth-server-demo で PR を作る直前に回すチェック。全体の ./mvnw verify（計算系センサー）と harness-reviewer（推論系センサー）を流し、docs の同期を確かめ、PR 説明を CLAUDE.md の形で用意する。「PR を作って」「PR 前のチェック」と言われたとき、コードの PR を作る前に必ず使う。
---

# PR 前のチェック（auth-server-demo）

ハーネスの全体像は `docs/harness.md`。Stop フックはターンごとに**速い**センサー（コンパイル＋`*RulesTest`）だけを流す。PR の前にここで**全部**を流す。

## 1. 計算系センサー（全体）

```bash
./mvnw -B -ntp clean verify
python3 .claude/hooks/harness_events.py pre-pr   # 落ちて直したものを記録へ（直してやり直すたびに流す）
```

- 規約テスト（`AuthRulesTest`・`CanaryRulesTest`）と Spring のテストまで回る（約30秒・Docker 不要・DB は H2）
- 落ちたら直してから次へ。**テストを消す・`@Disabled` にする・`rules:allow` を理由なしで書く、で緑にしない**
- 規約テストの違反は `target/surefire-reports/*RulesTest.txt` に直し方つきで出る
- ルールを足した・変えたなら、`CanaryRulesTest` に「当たるべき見本」と「当たってはいけない見本」を足す

## 2. 推論系センサー

`harness-reviewer` は読み取り専用（Read・Grep・Glob だけ）なので、git の情報を先にファイルで渡す（1. の `clean` の後に作る）：

```bash
R=target/harness/review; rm -rf $R; mkdir -p $R/base
git fetch -q origin main
git diff origin/main...HEAD > $R/branch.diff
git diff HEAD > $R/uncommitted.diff
git status --short > $R/status.txt
git log --format='%h %s' origin/main..HEAD > $R/log.txt
{ git merge-base origin/main HEAD; git rev-parse HEAD; } > $R/refs.txt
```

そのうえでサブエージェントに頼む（プロンプト例：「target/harness/review/ の差分をレビューして。重点は …」）。
報告は丸ごと `target/harness/review/report.md` に保存し、末尾の ```jsonl ブロックを記録へ回す（`.git/harness/events.jsonl` に周回番号つきで残る）：

```bash
python3 .claude/hooks/harness_events.py reviewer target/harness/review/report.md
```

- 🔴 は直して 1. からやり直す
- 🟡 は PR 説明の「判断を仰ぎたい点」に書く（直すなら直す）

## 3. docs の同期

- [ ] 規約を足した・変えたなら `docs/harness.md` §3 と `CLAUDE.md` を直した
- [ ] 環境変数を足したなら `.env.example`（名前とダミー値だけ）と README を直した
- [ ] 判断してもらった内容を `docs/harness.md` か `CLAUDE.md` に残した

## 4. PR

- タイトル・コミットは Conventional Commits（`feat: …`・`fix: …`・`security: …`・`docs: …`・`ci: …`・`test: …`）
- 説明に 1. と 2. の結果（テスト件数・🔴 が 0 件であること・🟡 の一覧）を書く
- **「人が聞きそうな前提」**の欄を置く。該当が無ければ「なし」と書く：
  - 運用で変えたくなる値（トークンの寿命・許可するリダイレクト先・上限）と、変えるのに何が要るか
  - 振る舞いの根拠になるテスト名
  - 既存の利用者・クライアント・DB に効く変更（設定の上書き・必須になった環境変数）
- 説明の**最後**に記録の隠しブロックを貼る（reviewer の各項目の扱いを `--outcome` で渡す）：

  ```bash
  python3 .claude/hooks/harness_events.py pr-block --outcome R1=fixed,Y1=wontfix
  ```

- ★**public リポジトリ**：PR 説明・コメント・記録に秘密情報や個人情報を入れない
- 「判断を仰ぎたい点」は1件ごとに **確認する理由** と **案ごとのメリット・デメリット** をセットで書く（CLAUDE.md）
- 作ったら**監視する**（CI・レビューコメント・マージ可否を追い、指摘には対応するか理由を返す）
