# Phantom Ethical Red Team — 統合版技術マニュアル

**バージョン**: v3.2.5 | **言語**: Python 3.11+ | **ステータス**: アーカイブ済（2026-04-03）

---

## 目次

1. [プロジェクト概要](#1-プロジェクト概要)
2. [アーキテクチャ詳細](#2-アーキテクチャ詳細)
3. [LLMプロバイダ抽象化層](#3-llmプロバイダ抽象化層)
4. [ツールシステム完全リファレンス](#4-ツールシステム完全リファレンス)
5. [セキュリティアーキテクチャ](#5-セキュリティアーキテクチャ)
6. [データモデル](#6-データモデル)
7. [永続化・セッション管理](#7-永続化セッション管理)
8. [MCPブリッジ設計・実装](#8-mcpブリッジ設計実装)
9. [環境カスタマイズ記録](#9-環境カスタマイズ記録)
10. [設定体系](#10-設定体系)
11. [テスト](#11-テスト)
12. [知見・メモリシステム](#12-知見メモリシステム)

---

## 1. プロジェクト概要

### 1.1 Phantomとは

完全自律型のAI Red Teamエージェント。人間の指示なしに攻撃戦略の立案から
エクスプロイト連鎖、カスタムツール動的生成までを自律的に遂行する。

### 1.2 コア原則

| 原則 | 説明 |
|---|---|
| **完全自律** | 攻撃戦略を自ら決定。固定キルチェーンなし |
| **動的ツール生成** | LLMがカスタムPythonスクリプトをオンザフライで生成・実行 |
| **0-day発見** | ファジングによる未知脆弱性の発見（既知CVEチェックだけでなく） |
| **完全エクスプロイト** | 永続化、横展開、データ窃取まで完全自動 |
| **ハードスコープ壁** | 認可スコープ内は完全自由、スコープ外は絶対ゼロ |
| **デブリーフ** | ミッション後に精密なタイムライン＋攻撃グラフを人間に報告 |

### 1.3 動作モード

| モード | コマンド | 説明 |
|---|---|---|
| V3 PAOR | `python agent/main.py --v3` (デフォルト) | 自律推論エンジン |
| V2 レガシー | `python agent/main.py --v2` | 線形フェーズループ |
| セッション復元 | `python agent/main.py --resume YYYYMMDD_HHMMSS` | 前回セッションから再開 |

---

## 2. アーキテクチャ詳細

### 2.1 ディレクトリ構成

```
phantom-ethical-redteam/
├── agent/                        # コアエージェント
│   ├── main.py                   # エントリポイント（383行）
│   ├── orchestrator.py           # V3 PAORループ統括（1671行）
│   ├── agent_client.py           # V2 レガシーループ
│   ├── providers/                # LLMプロバイダ抽象化
│   │   ├── __init__.py           # ファクトリ（get_provider）
│   │   ├── base.py               # 抽象基底クラス
│   │   ├── anthropic_provider.py # Anthropic（OAuth対応改修済）
│   │   ├── openai_provider.py    # OpenAI/Grok/DeepSeek
│   │   ├── ollama_provider.py    # Ollama（XMLフォールバック）
│   │   ├── gemini_provider.py    # Google Gemini
│   │   └── mistral_provider.py   # Mistral
│   ├── reasoning/                # 自律推論エンジン
│   │   ├── hypothesis_engine.py  # 仮説優先度キュー（683行）
│   │   ├── planner.py            # XMLプラン解析
│   │   ├── reflector.py          # 停滞検出・ピボット
│   │   ├── strategist.py         # 攻撃チェーン分析
│   │   ├── context_manager.py    # トークン予算管理（304行）
│   │   └── types.py              # AttackState, AttackPlan
│   ├── tools/                    # 27ツール
│   │   ├── __init__.py           # 自動検出レジストリ
│   │   ├── forge.py              # 動的ツール生成
│   │   ├── scope_checker.py      # スコープ強制
│   │   ├── sandbox.py            # サンドボックス実行
│   │   └── ... (23ツール)
│   ├── memory/                   # 構造化メモリ
│   │   ├── mission_memory.py     # 知識ベース
│   │   ├── persistence.py        # SQLite永続化（681行）
│   │   └── timeline.py           # タイムライン
│   ├── models/                   # データモデル
│   │   ├── findings.py           # Finding, Hypothesis, TargetInfo
│   │   ├── plans.py              # AttackPlan, AttackAction
│   │   ├── graph.py              # AttackGraph
│   │   ├── events.py             # Event, EventBus
│   │   └── state.py              # MissionState
│   └── utils/                    # ユーティリティ
├── prompts/                      # LLMプロンプトテンプレート
├── web/                          # Flask Webダッシュボード
├── tests/                        # テストスイート
├── scopes/                       # 認可ターゲット定義
├── logs/                         # セッション出力
├── mcp_bridge.py                 # MCPブリッジ（カスタム追加）
├── .mcp.json                     # Claude Code MCP設定（カスタム追加）
├── config.yaml                   # メイン設定
├── requirements.txt              # 依存パッケージ
└── .venv/                        # Python仮想環境（カスタム追加）
```

### 2.2 PAOR ループ（V3エンジンの中核）

```
                    ┌───────────────────────┐
                    │    ミッション開始       │
                    │  burst_launch()        │
                    │  12仮説/ターゲット生成  │
                    └───────────┬───────────┘
                                ▼
┌────────────────── PAORサイクル（仮説枯渇まで繰返し）──────────────────┐
│                                                                      │
│   ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌──────────┐ │
│   │   PLAN     │───▶│    ACT     │───▶│  OBSERVE   │───▶│ REFLECT  │ │
│   │            │    │            │    │            │    │          │ │
│   │ LLM呼出    │    │ ツール実行  │    │ 結果解析    │    │ 停滞検出  │ │
│   │ XML解析    │    │ 最大4並列   │    │ Finding抽出 │    │ ピボット  │ │
│   │ 並列強制   │    │ scope_guard │    │ グラフ更新  │    │ 判断     │ │
│   └────────────┘    └────────────┘    │ 仮説追加   │    └──────────┘ │
│         ▲                             └────────────┘         │       │
│         │                                                    │       │
│         │            ┌────────────┐                          │       │
│         │            │ STRATEGIST │ ← 5ターンごと             │       │
│         │            │ チェーン分析│                          │       │
│         │            └────────────┘                          │       │
│         └────────────────────────────────────────────────────┘       │
│                                                                      │
│   完了条件: 仮説キュー枯渇 / ターン上限 / ユーザー中断               │
└──────────────────────────────────────────────────────────────────────┘
                                ▼
                    ┌───────────────────────┐
                    │    デブリーフ生成       │
                    │  findings.json         │
                    │  report.html           │
                    │  attack_graph          │
                    └───────────────────────┘
```

### 2.3 Orchestrator（orchestrator.py, 1671行）

PAORループ全体を統括するクラス。

**主要メソッド**:

| メソッド | 行 | 役割 |
|---|---|---|
| `run_mission(scope_targets)` | メイン | ミッション全体実行→debrief返却 |
| `_build_initial_message(targets)` | 初期化 | burst_launch + 初期ユーザーメッセージ構築 |
| `_plan_phase()` | PLAN | システムプロンプト構築→LLM呼出→XML解析 |
| `_enforce_parallel_tools(calls)` | PLAN | ツール数<2なら再呼出を要求 |
| `_act_phase(tool_calls)` | ACT | ThreadPoolExecutorで並列実行 |
| `_observe_phase(calls, results, text)` | OBSERVE | Finding抽出、グラフ更新、仮説追加 |
| `_reflect_phase()` | REFLECT | reflector呼出、停滞時ピボット |
| `_run_strategist()` | STRATEGIST | 5ターンごとの攻撃チェーン分析 |
| `_build_system_prompt()` | 補助 | 状態注入付きシステムプロンプト構築 |
| `_compact_old_tool_results(msgs)` | 補助 | 古いツール結果を400文字に圧縮 |
| `_save_state()` | 永続化 | state.jsonにアトミック書込（毎ターン） |
| `load_state(session_dir)` | 復元 | --resume用セッション復元 |
| `_debrief()` | 終了 | 最終レポート・攻撃グラフ生成 |
| `_handle_pause()` | 制御 | Ctrl+Cでの一時停止処理 |

**内部状態**:

```python
self.attack_state: AttackState       # 計画・仮説・発見
self._findings: list[dict]            # 全発見脆弱性
self._mission_memory: MissionMemory   # 構造化知識ベース
self._hypothesis_engine: HypothesisEngine  # 優先度キュー
self.attack_graph: AttackGraph        # 有向グラフ
self.event_bus: EventBus              # イベントストリーム
self.mission_state: MissionState      # フェーズ状態マシン
self._messages: list[dict]            # LLM会話履歴
self._turn: int                       # 現在ターン
```

### 2.4 HypothesisEngine（hypothesis_engine.py, 683行）

攻撃仮説の優先度キュー管理。ミッションは「仮説が枯渇するまで」実行される。

**優先度定数**:
```python
PRI_CRITICAL   = 1.0   # 認証バイパス、RCE
PRI_HIGH       = 0.8   # SQLi、SSTI、情報漏洩
PRI_MEDIUM     = 0.6   # 情報列挙
PRI_LOW        = 0.4   # エッジケース
PRI_BACKGROUND = 0.2   # パッシブ情報収集
```

**仮説状態遷移**: `pending → in_progress → confirmed | disproved`

**burst_launch(targets)**: ターゲットごとに12個のティア別仮説を初期生成:
- Critical: SQLi、認証バイパス
- High: 情報漏洩、.env/git露出
- Medium: サービス列挙
- Low: エッジケース

**フォローアップルール**（Finding確認時に自動生成）:

| 発見カテゴリ | 追加仮説 |
|---|---|
| Injection (SQLi) | blind SQLi, time-based, SSTI |
| Exposure (.env, config) | クレデンシャル読取、バックアップ検索 |
| Auth weakness | パスワード再利用、権限昇格 |
| CVE確認 | リモートエクスプロイト、横展開 |
| ポート (SSH, DB) | デフォルトクレデンシャル、外部アクセス |

**終了条件**:
1. キュー空 + N連続ラウンド新仮説なし (`dry_round_threshold`)
2. ウォールクロック時間超過 (`max_wall_seconds`)
3. 手動 `force_stop()`

### 2.5 PlanningLayer（planner.py）

LLM出力に埋め込まれたXMLプランブロックを解析:

```xml
<plan_create objective="..." priority="0.95" hypothesis="h_id">
  <action tool="run_nmap" args='{"target":"10.0.0.1"}' priority="0.9"/>
  <action tool="run_nuclei" args='{"target":"10.0.0.1"}' depends_on="prev"/>
</plan_create>

<plan_update id="p_id">
  <action_status id="a_id" status="done" summary="3 ports found"/>
</plan_update>

<plan_abandon id="p_id" reason="hypothesis disproved"/>
<hypothesis_update id="h_id" confidence="confirmed" evidence="..."/>
```

### 2.6 Reflector（reflector.py）

3ターンごと（または重大発見時）にメタ認知的評価:

```xml
<reflection>
  <observation>学んだこと</observation>
  <decision>方針転換すべきか</decision>
  <action>計画Xを放棄、発見Yをエスカレート</action>
</reflection>
```

**停滞検出**: N連続ターンで新発見なし → PIVOT イベント発行 → 別攻撃ベクトルへ切替

### 2.7 Strategist（strategist.py）

5ターンごとの高次分析:
- 攻撃チェーン特定: HOST → SERVICE → VULN → CRED → DATA
- カバレッジ計算: ターゲット探索完了率
- 推奨: 「未探索の高価値ターゲット: 3306/MySQL on 10.0.0.5」

### 2.8 ContextManager（context_manager.py, 304行）

プロバイダのトークン上限に応じてプロンプト各セクションに予算配分:

```python
PROVIDER_LIMITS = {
    "anthropic": 200_000,
    "openai":    128_000,
    "grok":      128_000,
    "gemini":    128_000,
    "mistral":   128_000,
    "deepseek":   64_000,
    "ollama":      8_000,
}

_DEFAULT_BUDGETS = {
    "system_prompt": 0.10,  # 10%
    "state_summary": 0.20,  # 20% — ミッションメモリ + 攻撃状態
    "graph_summary": 0.10,  # 10% — 攻撃グラフ
    "hypotheses":    0.10,  # 10% — 仮説一覧
    "last_plan":     0.10,  # 10% — 現在の計画
    "conversation":  0.30,  # 30% — 直近の会話
    "tool_results":  0.10,  # 10% — 最新ツール結果
}
```

**小コンテキスト最適化** (`≤16K`):
- ツール結果を500文字に圧縮
- 攻撃チェーン詳細を省略
- 古い会話を積極的に切り捨て

---

## 3. LLMプロバイダ抽象化層

### 3.1 BaseLLMProvider（base.py）

```python
class BaseLLMProvider(ABC):
    MAX_RETRIES = 3
    RETRY_BACKOFF = 2.0  # エクスポネンシャルバックオフ
    TIMEOUT = 120        # 秒

    @abstractmethod
    def convert_tools(self, tools: list) -> list:
        """Anthropic形式のツール仕様をプロバイダ固有形式に変換"""

    @abstractmethod
    def call(self, messages, system_prompt, tools) -> tuple[list[str], list[dict]]:
        """1回のAPI呼出。(text_blocks, tool_calls) を返す
        tool_calls: [{"id": str, "name": str, "input": dict}, ...]"""

    def call_with_retry(self, messages, system_prompt, tools) -> tuple:
        """エクスポネンシャルバックオフ付きリトライラッパー"""
```

### 3.2 プロバイダ一覧

| プロバイダ | クラス | デフォルトモデル | ツール形式 | 認証 |
|---|---|---|---|---|
| `anthropic` | AnthropicProvider | claude-sonnet-4-6 | ネイティブ tool_use | APIキー / **OAuth** |
| `openai` | OpenAIProvider | gpt-5.4 | ネイティブ tool_calls | APIキー |
| `ollama` | OllamaProvider | deepseek-v3.2:cloud | XMLフォールバック | 不要 |
| `gemini` | GeminiProvider | gemini-3.0-pro | ネイティブ | APIキー |
| `mistral` | MistralProvider | mistral-large-latest | ネイティブ | APIキー |
| `grok` | OpenAIProvider | grok-4-20-beta | ネイティブ | XAI_API_KEY |
| `deepseek` | OpenAIProvider | deepseek-chat-v3.2 | ネイティブ | APIキー |
| `llamacpp` | OpenAIProvider | 自動検出 | ネイティブ | 不要 |

### 3.3 OAuth認証実装（カスタム改修）

`anthropic_provider.py` に以下を追加:

```python
class AnthropicProvider(BaseLLMProvider):
    def __init__(self, api_key, model=None, oauth_config=None):
        # oauth_config: {
        #   "refresh_token": str,
        #   "client_id": str,
        #   "client_secret": str (optional),
        #   "token_url": str,
        #   "expires_at": float (optional)
        # }

    def _is_token_expired(self) -> bool:
        # 有効期限の60秒前にTrueを返す（バッファ）

    def _refresh_oauth_token(self) -> None:
        # POSTでトークンエンドポイントにrefresh_tokenを送信
        # 新しいaccess_token, refresh_token, expires_inを取得
        # Anthropicクライアントを新トークンで再作成

    def _ensure_valid_token(self) -> None:
        # スレッドセーフ（threading.Lock）
        # ダブルチェックロッキングパターン

    def call_with_retry(self, ...):
        # 401エラー検出時にトークンリフレッシュしてリトライ
```

**環境変数**:

| 変数 | 説明 |
|---|---|
| `ANTHROPIC_OAUTH_ACCESS_TOKEN` | OAuthアクセストークン |
| `ANTHROPIC_OAUTH_REFRESH_TOKEN` | リフレッシュトークン |
| `ANTHROPIC_OAUTH_CLIENT_ID` | クライアントID |
| `ANTHROPIC_OAUTH_CLIENT_SECRET` | クライアントシークレット（任意） |

### 3.4 llamacpp プロバイダ（カスタム追加）

OpenAI互換APIを持つllama.cppサーバーに接続:

```python
# providers/__init__.py に追加
if name == "llamacpp":
    from .openai_provider import OpenAIProvider
    base_url = config.get("llamacpp_base_url", "http://localhost:8080/v1")
    api_key = config.get("api_key") or "no-key"
    return OpenAIProvider(api_key=api_key, model=model or "default", base_url=base_url)
```

### 3.5 プロバイダファクトリ（__init__.py）

```python
def get_provider(config: dict) -> BaseLLMProvider:
    name = config.get("provider", "anthropic").lower()
    # nameに応じて対応クラスのみimport → 未インストールSDKのImportError防止
    # anthropic → auth_method分岐（api_key / oauth）
    # llamacpp → OpenAIProvider + base_url
```

---

## 4. ツールシステム完全リファレンス

### 4.1 登録メカニズム

```python
# agent/tools/__init__.py

TOOL_REGISTRY: dict[str, callable] = {}  # name → function
TOOL_SPECS: list[dict] = []              # Anthropic JSON Schema形式

# 方法1: 手動登録（コアツール13個）
from .nuclei import run as run_nuclei, TOOL_SPEC as nuclei_spec

# 方法2: @register_tool(TOOL_SPEC) デコレータ
# 方法3: importlib自動検出（TOOL_SPEC + run属性を持つモジュール）
```

**TOOL_SPEC形式**（Anthropic tool_use互換）:
```python
TOOL_SPEC = {
    "name": "run_nmap",
    "description": "Port scanning with Nmap...",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "scan_type": {"type": "string", "enum": ["quick","service","full","vuln"]},
        },
        "required": ["target"],
    },
}
```

### 4.2 全27ツール一覧

#### 偵察（Reconnaissance）

| ツール名 | シグネチャ | スコープ |
|---|---|---|
| `run_nmap` | `(target, ports="-", scan_type="service", timeout=300) → str` | YES |
| `run_whatweb` | `(target, aggression=1) → str` | YES |
| `run_recon` | `(domain) → str` | YES |

#### スキャン・列挙（Scanning & Enumeration）

| ツール名 | シグネチャ | スコープ |
|---|---|---|
| `run_nuclei` | `(target, templates="http/cves", severity="critical,high") → str` | YES |
| `run_sqlmap` | `(url, level=3, risk=3, timeout=300) → str` | YES |
| `run_ffuf` | `(url, wordlist="") → str` | YES |
| `run_wpscan` | `(target, api_token="") → str` | YES |
| `run_graphql_enum` | `(target, endpoint="", depth="full") → str` | YES |
| `run_payloads` | `(category, for_ffuf=False, ffuf_url="") → str` | NO |

#### エクスプロイト・横展開（Exploitation）

| ツール名 | シグネチャ | スコープ |
|---|---|---|
| `fetch_exploit` | `(query="", execute=False, target="", **kwargs) → str` | YES(実行時) |
| `run_metasploit` | `(action, module="", target="", options=None, ...) → str` | YES(exploit/aux時) |
| `run_hydra` | `(target, service="http-form", userlist="", passlist="", form_params="") → str` | YES |
| `run_jwt_attacks` | `(target="", token="", action="analyze") → str` | YES(fetch時) |
| `run_privesc_check` | `(check="auto") → str` | NO |
| `run_bettercap` | `(target="", interface="", module="net.probe", duration=30) → str` | YES(target時) |

#### 証拠・レポート（Evidence & Reporting）

| ツール名 | シグネチャ | スコープ |
|---|---|---|
| `take_screenshot` | `(url, full_page=False) → str` | YES |
| `generate_report` | `(title, content, generate_pdf=False) → str` | NO |
| `read_log` | `(filename="") → str` | NO |
| `calculate_risk_score` | `(findings=None, **kwargs) → str` | NO |
| `compare_missions` | `(session_a, session_b) → str` | NO |

#### ユーティリティ（Utilities）

| ツール名 | シグネチャ | スコープ |
|---|---|---|
| `check_scope` | `(target="", **kwargs) → str` | ツール自体がスコープ検証 |
| `configure_auth` | `(auth_type, value, target="") → str` | NO |
| `set_stealth_profile` | `(profile="") → str` | NO |
| `cleanup_temp` | `() → str` | NO |
| `request_human_input` | `(question) → str` | NO |
| `generate_phish_template` | `(target, scenario="phishing_email") → str` | NO |
| `generate_zphisher_template` | `(target, template="instagram") → str` | NO |

### 4.3 動的ツール生成 — forge_tool（forge.py）

Phantomの最大の差別化機能。LLMがカスタムPythonスクリプトを動的に生成・実行する。

**フロー**:
```
LLM: forge_tool 呼出
  │ {description, target, context}
  ▼
DynamicToolForge:
  1. LLMにスクリプト生成を依頼（forge_tool_prompt.txt テンプレート使用）
  2. AST静的解析:
     - 禁止import検出（os.system, subprocess[許可外], pickle, importlib）
     - 禁止ビルトイン検出（eval, exec, compile, __import__）
     - ネットワークターゲット検証（全IP/ドメインをスコープ照合）
     - 最大500行 / 50KB制限
     - 相対import禁止
  3. サンドボックス実行（sandbox.py）:
     - Linux: seccompフィルタ（利用可能時）
     - メモリ制限: 512MB（設定可能）
     - タイムアウト: 60秒（最大300秒）
     - 出力制限: 10MB
     - 環境スクラビング: APIキー等を除去
  4. 結果返却: [CRITICAL]/[HIGH]/[MEDIUM]/[LOW]/[INFO] タグ付き
```

---

## 5. セキュリティアーキテクチャ

### 5.1 スコープ強制（多層防御）

```
ツール呼出 → scope_guard(target) → None（許可）/ str（拒否メッセージ）

チェック順序:
  1. ホスト名抽出（URL, IP, CIDR対応）
  2. 完全一致: hostname in scope_targets
  3. サブドメイン一致: hostname.endswith("." + scope_target)
  4. CIDR一致: ipaddress.ip_address(hostname) in network
  5. 全不一致 → "SCOPE VIOLATION" エラー返却

バイパス防止:
  - userinfo付きURL拒否（http://scope.com@evil.com）
  - ドメイン小文字正規化
  - 不正入力拒否
```

**適用ツール**: 13/27ツールがscope_guardを内部呼出。

### 5.2 サンドボックス実行（sandbox.py）

```python
@dataclass(frozen=True)
class SandboxConfig:
    timeout: int = 60
    max_memory_mb: int = 512
    max_output_bytes: int = 10_000_000
    allowed_network_targets: tuple[str, ...] = ()
    workspace_dir: str | None = None
```

### 5.3 禁止リスト

| カテゴリ | 禁止項目 |
|---|---|
| Import | os.system, subprocess（許可リスト外）, pickle, importlib, pathlib |
| ビルトイン | eval, exec, compile, `__import__` |
| 環境変数 | ANTHROPIC_*, OPENAI_*, AWS_*, DOCKER_*, *TOKEN*, *PASSWORD* |
| ドメイン | pastebin.com, ngrok.io, webhook.site（データ流出防止） |

---

## 6. データモデル

### 6.1 Finding

```python
@dataclass
class Finding:
    id: str              # UUID
    severity: str        # critical | high | medium | low | info
    category: str        # cve | misconfig | credential | exposure | injection
    title: str           # "SQL Injection on /search"
    target: str          # ホスト名/URL
    evidence: str        # 生の証拠
    tool_source: str     # "run_nuclei"
    timestamp: datetime
    cvss: float | None
    cve_id: str | None
    remediation: str | None
    screenshot_path: str | None
```

### 6.2 ActionRecord / Hypothesis / TargetInfo

```python
@dataclass
class ActionRecord:
    id, tool, parameters, result_summary, findings_produced, timestamp, success

@dataclass
class Hypothesis:
    id, statement, confidence (speculative|probable|confirmed|disproved)
    evidence_for, evidence_against, created_turn, last_updated_turn

@dataclass
class TargetInfo:
    host, ports: list[int], services: dict[int, str]
    technologies: list[str], os_guess: str | None
```

### 6.3 AttackGraph（有向グラフ）

```python
class NodeType(Enum):
    HOST          # 10.0.0.1
    SERVICE       # Apache 2.4.51 on :80
    VULNERABILITY # CVE-2023-2745
    CREDENTIAL    # admin:password
    ACCESS        # SSH shell, RCE
    DATA          # /etc/shadow

class EdgeType(Enum):
    RUNS_ON       # SERVICE → HOST
    EXPOSES       # SERVICE → VULNERABILITY
    EXPLOITS      # VULNERABILITY → technique
    GRANTS        # exploit → CREDENTIAL/ACCESS
    LEADS_TO      # ACCESS → DATA
    EXFILTRATES   # データ窃取

# 使用例チェーン: HOST → SERVICE → VULN → CRED → DATA
```

### 6.4 MissionState（状態マシン）

```
INIT → RECON → SCANNING → ENUMERATION → EXPLOITATION → POST_EXPLOIT → REPORTING → COMPLETE
         ↑__________________________|  （ピボット時にループバック）
```

### 6.5 Event / EventBus

```python
class EventType(Enum):
    TOOL_INVOKED, TOOL_COMPLETED, TOOL_FAILED
    FINDING_DISCOVERED, FINDING_CONFIRMED, FINDING_FALSE_POSITIVE
    DECISION, PIVOT, HYPOTHESIS, STALL_DETECTED
    PHASE_TRANSITION, SCOPE_CHECK, RATE_LIMITED
    SESSION_START, SESSION_PAUSE, SESSION_RESUME, SESSION_END

class Severity(Enum):
    CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE

@dataclass(frozen=True)  # イミュータブル
class Event:
    id, mission_id, timestamp, turn, event_type, phase
    tool_name, tool_input, tool_output, tool_duration_ms
    severity, target, title, cve_ids, cvss_score
    reasoning, parent_event_ids, metadata
```

---

## 7. 永続化・セッション管理

### 7.1 SQLiteスキーマ（persistence.py, 681行）

```sql
PRAGMA journal_mode = WAL;     -- 並行読取（ライブダッシュボード用）
PRAGMA foreign_keys = ON;      -- 参照整合性
PRAGMA synchronous = NORMAL;   -- パフォーマンス vs 耐久性

-- 8テーブル
missions        -- ミッション状態（id, phase, turn, scope_hash, ...）
events          -- イベントタイムライン
findings        -- 発見した脆弱性
actions         -- 実行したアクション
hypotheses      -- 攻撃仮説
targets         -- ターゲット情報
graph_nodes     -- 攻撃グラフノード
graph_edges     -- 攻撃グラフエッジ

-- 16インデックス（mission_id, turn, severity, target等）
```

### 7.2 state.json（セッション復元用）

```json
{
  "turn": 15,
  "messages": [...],         // LLM会話履歴全体
  "attack_state": {...},     // AttackState.to_dict()
  "attack_graph": {...},     // AttackGraph.to_dict()
  "mission_state": {
    "phase": "exploitation",
    "mission_id": "20260405_143000"
  }
}
```

**アトミック書込**: `tempfile.mkstemp()` → `os.replace()` でクラッシュ耐性。

### 7.3 セッション出力ディレクトリ

```
logs/YYYYMMDD_HHMMSS/
├── agent.log          # デバッグログ（秘密値はリダクト）
├── state.json         # セッション状態（復元用）
├── mission.db         # SQLiteデータベース
├── findings.json      # 構造化脆弱性レポート
├── debrief.json       # ミッションサマリ
└── report.html        # HTMLレポート
```

---

## 8. MCPブリッジ設計・実装（カスタム追加）

### 8.1 設計思想

Phantomのオーケストレータ（PAORループ）を使わず、Claude Code CLI（OAuth/Max 20xプラン）を
LLM頭脳として使用し、Phantomの27ツールをMCPサーバー経由で呼び出す構成。

```
Claude Code CLI (OAuth認証 / Max 20x / コスト0)
  │ MCP (stdio transport)
  ▼
mcp_bridge.py (薄いルーター)
  │ TOOL_REGISTRY[name](**args)
  ▼
Phantom ツール群 (既存コード、変更なし)
  ├── scope_checker (スコープ強制)
  ├── sandbox (サンドボックス実行)
  └── 各ツール (nmap, nuclei, ...)
```

### 8.2 ブリッジがやること

1. `TOOL_SPECS` から全ツールの名前・説明を取得
2. 各ツール関数を `mcp.add_tool()` で FastMCP に登録
3. Claude Code からの呼出を `TOOL_REGISTRY[name](**args)` にそのまま転送
4. 結果をそのまま返す

### 8.3 ブリッジがやらないこと

- スコープチェック（Phantom各ツール内で実施済み）
- 引数バリデーション（Phantom各ツール内で実施済み）
- 状態管理（Claude Codeのコンテキストが担当）
- エラーハンドリング（Phantom側の例外をそのまま伝播）

### 8.4 実装（mcp_bridge.py, 99行）

```python
from fastmcp import FastMCP
from tools import TOOL_REGISTRY, TOOL_SPECS

mcp = FastMCP("Phantom Security Tools")

# **kwargs問題の解決:
# FastMCPは**kwargsを持つ関数を拒否するため、
# 明示的パラメータのみの新シグネチャを持つラッパーを生成
def _strip_kwargs(func):
    sig = inspect.signature(func)
    explicit_params = [p for p in sig.parameters.values()
                       if p.kind not in (VAR_KEYWORD, VAR_POSITIONAL)]
    wrapper.__signature__ = sig.replace(parameters=explicit_params)
    return wrapper

# 全27ツールを動的登録
for tool_name, tool_func in TOOL_REGISTRY.items():
    fn = _strip_kwargs(fn) if _needs_kwargs_wrapper(fn) else fn
    fn.__name__ = tool_name        # FastMCPがツール名として使用
    fn.__doc__ = description        # FastMCPがツール説明として使用
    mcp.add_tool(fn)

mcp.run(transport="stdio")
```

### 8.5 MCP設定ファイル（.mcp.json）

```json
{
  "mcpServers": {
    "phantom": {
      "type": "stdio",
      "command": "/home/noir/phantom-ethical-redteam/.venv/bin/python",
      "args": ["/home/noir/phantom-ethical-redteam/mcp_bridge.py"],
      "env": {
        "PYTHONPATH": ".../agent:..."
      }
    }
  }
}
```

### 8.6 検証結果

```
$ claude mcp list
phantom: ✓ Connected

登録済みツール: 27/27
check_scope("10.129.245.50") → "IN SCOPE"
run_nmap("10.129.245.50", scan_type="quick") → ポート22, 80検出
```

---

## 9. 環境カスタマイズ記録

### 9.1 変更ファイル一覧

| ファイル | 変更内容 | 種別 |
|---|---|---|
| `config.yaml` | provider→anthropic, auth_method→oauth, model→claude-sonnet-4-6, llamacpp_base_url追加 | 設定変更 |
| `agent/providers/__init__.py` | anthropic OAuth分岐追加、llamacppプロバイダ追加、PROVIDERS配列更新 | コード変更 |
| `agent/providers/anthropic_provider.py` | OAuth対応全面改修（oauth_config, トークンリフレッシュ, 401リトライ） | コード変更 |
| `scopes/current_scope.md` | HTBターゲット `10.129.245.50` + `kobold.htb` 設定 | 新規作成 |
| `mcp_bridge.py` | MCPブリッジサーバー（FastMCP, 27ツール動的登録） | **新規ファイル** |
| `.mcp.json` | Claude Code MCP設定 | **新規ファイル** |
| `.claude/settings.json` | MCPサーバー権限設定 | **新規ファイル** |
| `.venv/` | Python仮想環境（全依存 + fastmcp） | **新規ディレクトリ** |

### 9.2 OS/ネットワーク設定

| 設定 | 値 |
|---|---|
| `/etc/hosts` | `10.129.245.50 kobold.htb bin.kobold.htb mcp.kobold.htb` |
| VPN | HTB OpenVPN → tun0 (10.10.15.43) |
| llama.cpp | `http://192.168.91.1:8080` (qwen3codernext-abliterated) |

### 9.3 config.yaml 変更詳細

```yaml
# 変更前
provider: "ollama"
model: "deepseek-v3.2:cloud"
api_key: ""

# 変更後
provider: "anthropic"
model: "claude-sonnet-4-6"
auth_method: "oauth"
api_key: ""
llamacpp_base_url: "http://192.168.91.1:8080/v1"
# OAuth設定はコメントテンプレートとして追加
```

### 9.4 AnthropicProvider OAuth改修詳細

**追加機能**:

| 機能 | 実装 |
|---|---|
| OAuthトークン管理 | `oauth_config` パラメータ（refresh_token, client_id, client_secret, token_url） |
| 自動トークンリフレッシュ | 有効期限60秒前に自動更新 |
| スレッドセーフ | `threading.Lock` でダブルチェックロッキング |
| 401リトライ | `call_with_retry` オーバーライド、認証エラー検出→リフレッシュ→再試行 |
| 認証エラー検出 | `_is_auth_error()`: HTTPステータス401、"unauthorized"文字列、クラス名"auth" |

---

## 10. 設定体系

### 10.1 config.yaml 完全リファレンス

| キー | デフォルト | 説明 |
|---|---|---|
| `provider` | `"ollama"` | LLMプロバイダ (anthropic/openai/grok/gemini/ollama/mistral/deepseek/llamacpp) |
| `model` | プロバイダ依存 | モデル名。空でデフォルト使用 |
| `auth_method` | `"api_key"` | 認証方式 (`api_key` / `oauth`) |
| `api_key` | `""` | APIキー（環境変数優先） |
| `llamacpp_base_url` | `"http://localhost:8080/v1"` | llama.cppサーバーURL |
| `ollama_host` | `"http://localhost:11434"` | OllamaサーバーURL |
| `log_dir` | `"logs"` | セッション出力ディレクトリ |
| `scope_file` | `"scopes/current_scope.md"` | スコープ定義ファイル |
| `debug` | `false` | デバッグログ有効化 |
| `autonomous` | `true` | V2用: ターン間の自動実行 |
| `max_autonomous_turns` | `50` | 最大ターン数 |
| `pause_every_n_turns` | `10` | V2用: N ターンごとに一時停止 |
| `interactive` | `true` | 対話モード |
| `sqlmap_timeout` | `300` | sqlmap タイムアウト（秒） |
| `nmap_timeout` | `300` | nmap タイムアウト（秒） |
| `ollama_timeout` | `300` | Ollama LLM タイムアウト（秒） |
| `metasploit_timeout` | `120` | Metasploit タイムアウト（秒） |
| `max_parallel_tools` | `4` | ツール並列実行数 |
| `requests_per_second` | `5` | HTTPレート制限 |
| `retry_max` | `3` | HTTPリトライ回数 |
| `retry_backoff` | `2` | リトライバックオフ倍率 |
| `context_compact_after` | `5` | 古い結果の圧縮開始ターン |
| `stall_threshold` | `5` | 停滞判定ターン数 |
| `stealth_profile` | `"normal"` | ステルスプロファイル (silent/stealthy/normal/aggressive) |

### 10.2 スコープファイル形式（scopes/current_scope.md）

```markdown
# Authorized Targets
10.129.245.50
kobold.htb
https://target.example.com
192.168.1.0/24

# Authorization: Pentest contract reference
# Date: 2026-04-05
```

対応形式: URL, ドメイン, IP, CIDR。`#` 行はコメント。

---

## 11. テスト

### 11.1 テストスイート

```bash
source .venv/bin/activate
python -m pytest tests/ -v              # 全テスト実行
python -m pytest tests/ -k "forge"      # キーワードフィルタ
python -m pytest tests/ --cov=agent     # カバレッジ
```

**結果**: 363 passed（TestOpenAIConversion 1件は既知の非関連失敗）

### 11.2 テストカテゴリ

| ファイル | テスト数 | 対象 |
|---|---|---|
| test_forge.py | 40+ | 動的スクリプト検証、import制限、サンドボックス |
| test_reasoning_*.py | 80+ | プランナー、リフレクター、ストラテジスト |
| test_models_*.py | 60+ | Finding、Plan、Graph、State モデル |
| test_scope_checker.py | 30+ | CIDR、サブドメイン、URL解析 |
| test_memory.py | 25+ | ミッションメモリクエリ |
| test_providers.py | 10+ | プロバイダインターフェース |

---

## 12. 知見・メモリシステム

### 12.1 Claude Code メモリシステム

Claude Codeは `~/.claude/projects/{project-path}/memory/` にファイルベースのメモリを持つ。
セッション間で永続化され、新セッション開始時に自動読込される。

### 12.2 メモリタイプ

| タイプ | 目的 | 保存タイミング |
|---|---|---|
| `user` | ユーザーの役割・好み・環境 | ユーザー情報を学んだ時 |
| `feedback` | 行動指針（やること/やらないこと） | 修正・確認を受けた時 |
| `project` | ミッション状況・進行記録 | 進行状況が変わった時 |
| `reference` | 外部リソース参照情報 | リソースの場所を学んだ時 |

### 12.3 保存済みメモリ

| ファイル | タイプ | 内容 |
|---|---|---|
| `user_noir.md` | user | Kali Linux, HTBペンテスター, 日本語, sudo password, Max 20x |
| `feedback_subdomain_wordlist.md` | feedback | 20K+ワードリスト使用の教訓 |
| `feedback_tmux_revshell.md` | feedback | tmuxによるリバースシェル管理パターン |
| `project_htb_kobold_mission.md` | project | Kobold攻略完了記録・攻撃チェーン |
| `reference_phantom_mcp_tools.md` | reference | 27ツール一覧とBashフォールバック方法 |

### 12.4 メモリの仕組み

```
MEMORY.md (インデックス — 各エントリ1行、~150文字)
  ├── feedback_*.md → 行動指針（失敗から学んだルール）
  ├── project_*.md  → ミッション状況
  ├── reference_*.md → 参照情報
  └── user_*.md     → ユーザープロファイル
```

**フロントマター形式**:
```markdown
---
name: Subdomain wordlist size
description: Always use 20K+ wordlists for vhost enumeration
type: feedback
---
（内容: Why + How to apply）
```

**セッション間の知見継承**:
新セッション開始 → MEMORY.md 自動読込 → 過去の教訓を踏まえた判断が可能。
例: 次回のHTB攻略では自動的に20K+ワードリストを使用し、
tmuxでリバースシェルを管理する。
