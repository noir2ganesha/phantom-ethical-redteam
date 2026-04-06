# Co-RedTeam 完全技術仕様書 — 実装ガイド

> **目的**: 本文書はローカルAIに渡し、Co-RedTeamフレームワークの再実装を行うための完全な技術仕様書である。論文（arXiv:2602.02164v2）の全設計・Appendixの全プロンプト・数理的背景・実装判断の根拠を統合し、実装に必要な情報を網羅する。
>
> **論文情報**: Pengfei He et al. (Michigan State University / Google Cloud AI Research), Feb 2026
>
> **ソースコード状況**: 未公開。ただし論文Appendixに全エージェントのプロンプト・スキーマ・ツール定義が記載されており、Google ADK（Apache 2.0, OSS）上での再実装が可能。

---

## 目次

1. [アーキテクチャ全体像](#1-アーキテクチャ全体像)
2. [技術スタックと依存関係](#2-技術スタックと依存関係)
3. [Orchestrator 仕様](#3-orchestrator-仕様)
4. [Stage I: Vulnerability Discovery 仕様](#4-stage-i-vulnerability-discovery-仕様)
5. [Stage II: Iterative Exploitation 仕様](#5-stage-ii-iterative-exploitation-仕様)
6. [Long-term Memory 仕様](#6-long-term-memory-仕様)
7. [ツール定義一覧](#7-ツール定義一覧)
8. [エージェント完全プロンプト](#8-エージェント完全プロンプト)
9. [データスキーマ定義](#9-データスキーマ定義)
10. [設定パラメータと推奨値](#10-設定パラメータと推奨値)
11. [評価ベンチマークと主要結果](#11-評価ベンチマークと主要結果)
12. [数理的背景と設計根拠](#12-数理的背景と設計根拠)
13. [実装ロードマップ](#13-実装ロードマップ)

---

## 1. アーキテクチャ全体像

### 1.1 システム構成図

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ORCHESTRATOR                                   │
│  ┌────────────────┐  ┌──────────────────────────────────────────────┐  │
│  │ 入力検証        │  │ 動的ルーティング                             │  │
│  │ - code_path    │  │ - vuln_description あり → Stage II 直行      │  │
│  │ - vuln_desc    │  │ - vuln_description なし → Stage I → II       │  │
│  └────────────────┘  └──────────────────────────────────────────────┘  │
│                                                                          │
│  ┌─────────── Stage I ────────────┐ ┌─────────── Stage II ───────────┐ │
│  │  VULNERABILITY DISCOVERY       │ │  ITERATIVE EXPLOITATION        │ │
│  │                                │ │                                 │ │
│  │  ┌──────────────────────────┐  │ │  ┌───────────────────────────┐ │ │
│  │  │ Analysis Agent           │  │ │  │ Planner Agent             │ │ │
│  │  │ tools: code_browser,     │  │ │  │ tools: code_browser,      │ │ │
│  │  │   vuln_doc, memory       │  │ │  │   vuln_doc, memory,       │ │ │
│  │  └──────────┬───────────────┘  │ │  │   validation_tool         │ │ │
│  │             │ vuln drafts       │ │  └──────────┬────────────────┘ │ │
│  │             ▼                   │ │             │ proposed action   │ │
│  │  ┌──────────────────────────┐  │ │             ▼                  │ │
│  │  │ Critique Agent           │  │ │  ┌───────────────────────────┐ │ │
│  │  │ tools: code_browser,     │  │ │  │ Validation Agent (tool)   │ │ │
│  │  │   vuln_doc               │  │ │  └──────────┬────────────────┘ │ │
│  │  └──────────┬───────────────┘  │ │    valid ──→│←── invalid → 戻る│ │
│  │             │ feedback           │ │             ▼                  │ │
│  │             ▼                   │ │  ┌───────────────────────────┐ │ │
│  │  反復 (max 3回)               │ │  │ Execution Agent           │ │ │
│  │             │                   │ │  │ env: Docker sandbox       │ │ │
│  │             ▼                   │ │  │ tools: run_bash,          │ │ │
│  │  validated_vulnerabilities ────→│→│  │   run_python              │ │ │
│  └────────────────────────────────┘ │  └──────────┬────────────────┘ │ │
│                                      │             │ exec result      │ │
│                                      │             ▼                  │ │
│                                      │  ┌───────────────────────────┐ │ │
│                                      │  │ Evaluation Agent          │ │ │
│                                      │  └──────────┬────────────────┘ │ │
│                                      │       success│ or feedback     │ │
│                                      │             ▼                  │ │
│                                      │  反復 (max 20回)              │ │
│                                      └───────────────────────────────┘ │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    LONG-TERM MEMORY (3層)                        │  │
│  │  [L1: Vulnerability Pattern] [L2: Strategy] [L3: Technical Action]│  │
│  │  Storage: Vector DB (embedding + cosine similarity)              │  │
│  │  全エージェントからツールとして参照可能                          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 4つの統合能力

| 能力 | 実装手段 | 対応コンポーネント |
|------|----------|-------------------|
| Security Grounding | CWE/OWASP ドキュメントRAG | `get_vulnerability_summary`, `query_vulnerability_docs` |
| Code-aware Analysis | コードブラウジングツール群 | `get_whole_file_structure_tool`, `read_file_tool`, `get_snippet_tool` 等 |
| Execution-driven Reasoning | Docker隔離環境での閉ループ | `run_bash`, `run_python` + Evaluation Agent |
| Experience Accumulation | 3層長期メモリ | `vulnerability_memory_tool` + embedding検索 |

---

## 2. 技術スタックと依存関係

### 2.1 必須コンポーネント

| コンポーネント | 論文での使用 | 代替候補（ローカル実装用） |
|---------------|-------------|-------------------------|
| Agent Framework | Google ADK (Python) | LangChain / LangGraph / 自作 |
| Backbone LLM | Gemini-2.5-pro / Gemini-3-pro | Qwen3-Coder / Llama / ローカルLLM |
| Embedding Model | gemini-embedding-001 | nomic-embed / bge / ローカル embedding |
| Vector DB | 未明示（embedding検索） | ChromaDB / Qdrant / pgvector |
| Execution Sandbox | Docker コンテナ | Docker / Podman |
| 脆弱性知識ベース | CWE Top 25 + OWASP Top 10 | 同左（公開データ） |

### 2.2 実装言語とフレームワーク

論文はGoogle ADK (Python) を使用。ADKのコア概念：
- `LlmAgent`: LLMベースのエージェント定義（name, model, instruction, tools, sub_agents）
- 厳密な入出力スキーマ（Pydantic-like）でエージェント間通信を規制
- ツールは Python関数として定義し、エージェントに割り当て

---

## 3. Orchestrator 仕様

### 3.1 責務

1. **入力検証**: code_path の存在確認、vuln_description の解析
2. **動的ルーティング**: vuln_description の有無で Stage I / Stage II を選択
3. **エージェント初期化**: 全エージェントインスタンスの生成とロール別ツール割当
4. **状態管理**: ワークフロー状態の監視と遷移制御
5. **終了判定**: 成功（PoC生成）/ 失敗（反復上限）/ 早期終了

### 3.2 状態遷移

```
INIT
  │ 入力検証成功
  ├──→ [vuln_desc なし] ──→ DISCOVERY ──→ EXPLOITATION ──→ FINALIZE
  └──→ [vuln_desc あり] ──────────────→ EXPLOITATION ──→ FINALIZE
                                              │
                                              ├──→ SUCCESS (PoC生成)
                                              └──→ FAILURE (反復上限 or 進捗なし)
```

### 3.3 実装擬似コード

```python
class Orchestrator:
    def __init__(self, config):
        self.backbone_llm = config.backbone_llm
        self.max_discovery_iterations = 3
        self.max_exploitation_iterations = 20
        
        # エージェント初期化
        self.analysis_agent = AnalysisAgent(
            llm=self.backbone_llm,
            tools=[code_browser_tools, vuln_doc_tools, memory_tool]
        )
        self.critique_agent = CritiqueAgent(
            llm=self.backbone_llm,
            tools=[code_browser_tools, vuln_doc_tools]
        )
        self.planner_agent = PlannerAgent(
            llm=self.backbone_llm,
            tools=[code_browser_tools, vuln_doc_tools, memory_tool, validation_tool]
        )
        self.execution_agent = ExecutionAgent(
            llm=self.backbone_llm,
            tools=[run_bash, run_python]  # Docker sandbox内
        )
        self.evaluation_agent = EvaluationAgent(
            llm=self.backbone_llm,
            tools=[]
        )
        self.memory = LongTermMemory(
            embedding_model=config.embedding_model,
            vector_db=config.vector_db,
            top_k=3
        )

    def run(self, code_path: str, vuln_description: str = None) -> VulnerabilityReport:
        # 入力検証
        assert os.path.exists(code_path), f"Code path not found: {code_path}"
        
        vulnerabilities = []
        
        # Stage I: Vulnerability Discovery
        if vuln_description is None:
            vulnerabilities = self._run_discovery(code_path)
        else:
            vulnerabilities = [parse_vuln_description(vuln_description)]
        
        # Stage II: Iterative Exploitation
        results = []
        for vuln in vulnerabilities:
            result = self._run_exploitation(code_path, vuln)
            results.append(result)
        
        return VulnerabilityReport(results=results)

    def _run_discovery(self, code_path: str) -> list:
        memory_context = self.memory.retrieve(code_path, layer="vulnerability_pattern")
        critic_feedback = None
        
        for iteration in range(self.max_discovery_iterations):
            # Analysis Agent: 脆弱性仮説生成
            vuln_drafts = self.analysis_agent.run(
                code_path=code_path,
                memory_context=memory_context,
                critic_feedback=critic_feedback
            )
            
            # Critique Agent: 検証と改善要求
            critique_result = self.critique_agent.run(
                vulnerability_list=vuln_drafts
            )
            
            # 全候補がApproved → 終了
            if all(r.status == "approved" for r in critique_result):
                break
            
            # フィードバックを次の反復に渡す
            critic_feedback = critique_result
        
        return [v for v in critique_result if v.status == "approved"]

    def _run_exploitation(self, code_path: str, vuln) -> ExploitResult:
        exploit_plan = None
        
        for iteration in range(self.max_exploitation_iterations):
            # Planner: 計画策定/改訂
            plan_output = self.planner_agent.run(
                code_path=code_path,
                vulnerability=vuln,
                exploit_plan=exploit_plan,
                execution_feedback=prev_feedback if iteration > 0 else None
            )
            exploit_plan = plan_output.exploit_plan
            proposed_action = plan_output.next_action
            
            # Validation: アクション検証
            validation = self.validation_agent.validate(
                proposed_action, exploit_plan, system_state
            )
            if not validation.is_valid:
                prev_feedback = validation.feedback
                continue
            
            # Execution: Docker sandbox内で実行
            exec_result = self.execution_agent.execute(proposed_action)
            
            # Evaluation: 結果評価
            eval_result = self.evaluation_agent.evaluate(
                exec_result, exploit_plan, vuln
            )
            
            if eval_result.status == "success":
                self.memory.store_success(vuln, exploit_plan, exec_result)
                return ExploitResult(success=True, evidence=exec_result)
            
            prev_feedback = eval_result.feedback
        
        self.memory.store_failure(vuln, exploit_plan)
        return ExploitResult(success=False)
```

---

## 4. Stage I: Vulnerability Discovery 仕様

### 4.1 Analysis Agent

**役割**: コードベースを体系的に解析し、証拠に基づく脆弱性仮説を生成する。

**入力スキーマ**:
```python
class AnalysisInput:
    code_path: str                          # 対象コードベースのパス
    memory_context: list[MemoryItem] = []   # 事前取得済みメモリ（オプション）
    critic_feedback: list[CritiqueResult] = []  # 前回のCritique結果（オプション）
```

**出力スキーマ**:
```python
class BrainstormOutputSchema:
    vulnerability_list: list[VulnerabilityDraft]

class VulnerabilityDraft:
    id: str              # "DRAFT-001" 形式
    class_name: str      # CWE形式: "CWE-79: Reflected XSS"
    description: str     # 脆弱性の明確な概要
    evidence: Evidence   # ファイル/行/スニペット
    risk_rationale: str  # 影響の根拠

class Evidence:
    source: CodeLocation    # 信頼されない入力の入口
    sink: CodeLocation      # 危険な処理箇所
    context: str            # 保護が不十分な理由
    
class CodeLocation:
    file: str
    line: int
    snippet: str
```

**動作フロー**:

```
[critic_feedback なし（初回）]
  1. SCAN: code_browser_tools でファイル構造マッピング
     → get_whole_file_structure_tool
     → read_readme_tool
     → エントリポイント・設定ファイル特定
  2. CONSULT MEMORY: vulnerability_memory_tool でキーワード検索
  3. SECURITY KNOWLEDGE: get_vulnerability_summary / query_vulnerability_docs
  4. DEEP DIVE: 分析戦略の適用 + get_snippet_tool で高リスクコード検査
  5. EVIDENCE COMPILATION: Source → Sink → Context の証拠チェーン構築
  6. OUTPUT: BrainstormOutputSchema 生成

[critic_feedback あり（2回目以降）]
  → "fix-it" タスク
  → Rejected/Needs Refinement の各候補について:
     - より良い証拠（具体的行番号）を探索
     - より強いリスク論証を構築
     - 不可能なら候補を棄却
```

**分析戦略**（プロンプト内で指示）:

| 戦略 | 目的 | 手法 | 対応CWE例 |
|------|------|------|----------|
| Taint Analysis | インジェクション欠陥 | エントリポイント → Dangerous Sink 追跡 | CWE-89 (SQLi), CWE-78 (OS Command), CWE-79 (XSS) |
| Trust Boundary Mapping | 認証/認可バイパス | 信頼境界での検証有無確認 | CWE-862 (Missing Authorization), CWE-306 |
| Configuration Audit | インフラ欠陥 | Dockerfile/設定/依存関係監査 | CWE-489 (Debug Code), CWE-798 (Hard-coded Credentials) |
| Business Logic Tracing | IDOR/ワークフローバイパス | 多段階操作のサーバ側検証追跡 | CWE-639 (IDOR), CWE-840 |

### 4.2 Critique Agent

**役割**: Analysis Agent の出力を独立検証し、リスク評価を付与する。

**入力スキーマ**:
```python
class CritiqueInput:
    vulnerability_list: list[VulnerabilityDraft]
```

**出力スキーマ**:
```python
class CritiqueOutput:
    review_results: list[CritiqueResult]

class CritiqueResult:
    vulnerability_id: str
    status: Literal["approved", "rejected", "needs_refinement"]
    estimated_risk_level: Literal["Critical", "High", "Medium", "Low", "Informational"]
    feedback: str   # 判定の具体的根拠
```

**リスクレベル定義**:

| レベル | 基準 |
|--------|------|
| Critical | エクスプロイトが自明/高確率 → 完全システム侵害 → 即時緊急対応 |
| High | エクスプロイトが高確率 → 重大データ損失/権限昇格 → 日単位の修復 |
| Medium | エクスプロイトが可能 → 限定的データ露出 → 標準的修復 |
| Low | エクスプロイトが困難/低影響 → リソースがある場合の修復 |
| Informational | ベストプラクティスの逸脱 → 直接リスクなし |

---

## 5. Stage II: Iterative Exploitation 仕様

### 5.1 Planner Agent

**役割**: エクスプロイト計画の策定・改訂、具体的アクションの生成。

**Exploit Plan データ構造**:
```python
class ExploitPlan:
    steps: list[PlanStep]
    overall_strategy: str
    current_step_index: int

class PlanStep:
    id: int
    goal: str                                       # このステップの目標
    action: str                                     # 実行コマンド/スクリプト
    status: Literal["planned", "in_progress", "done", "blocked"]
    dependencies: list[int] = []                    # 先行ステップID
    feedback: str = ""                              # 実行後フィードバック
```

**Grounding Phase（初回計画策定時）**:
```
1. 脆弱性記述と証拠チェーンの解釈
2. query_vulnerability_docs で関連セキュリティ知識取得
3. code_browser_tools でコードベーススキャン（技術スタック/攻撃面の理解）
4. vulnerability_memory_tool で過去の成功戦略/技術パターン参照
5. 初期 ExploitPlan の策定
```

**Plan Revision（各実行サイクル後）**:
```
PLAN_REVISION(plan, exec_result, eval_feedback):
  1. 試行ステップのstatus更新 → done or blocked
  2. blocked時: 修正ステップを挿入（パス調整、ペイロード切替、代替コマンド等）
  3. 将来ステップの前方伝播的見直し（仮定が無効化されたステップを修正/破棄）
  4. 次の実行可能アクションを生成
```

### 5.2 Validation Agent

**役割**: Planner のアクション提案を実行前に検証するゲート。Planner に対してツールとして公開される。

**検証チェック項目**:
```python
class ValidationResult:
    is_valid: bool
    checks: dict  # 各チェック項目の結果
    feedback: str  # 無効時の修正指示

# チェック項目:
# 1. well_formedness: コマンド構文が正しいか
# 2. syntactic_soundness: 参照ファイル/パス/変数が存在するか
# 3. goal_alignment: アクションが意図した目標と整合するか
# 4. state_compatibility: 現在のシステム状態と互換するか
```

### 5.3 Execution Agent

**役割**: Docker sandbox内でのコマンド/スクリプト実行。

**利用可能ツール**:
- `run_bash(command: str) -> ExecutionResult`: Bashコマンド実行
- `run_python(script: str) -> ExecutionResult`: Pythonスクリプト実行

**出力**:
```python
class ExecutionResult:
    status: Literal["success", "error", "timeout"]
    stdout: str
    stderr: str
    exit_code: int
    execution_time_seconds: float
```

**Docker隔離要件**:
- ターゲットコードベースがコンテナ内にマウントされている
- ネットワークアクセスはターゲットサービスへのみ（設定による）
- ホストファイルシステムへの書き込み不可
- 実行タイムアウト設定

### 5.4 Evaluation Agent

**役割**: 実行結果を高レベル推論シグナルに変換。

**出力スキーマ**:
```python
class EvaluationResult:
    status: Literal["success", "partial_progress", "failure", "environment_error"]
    goal_achieved: bool
    deviations: str          # 予期しない挙動の記述
    error_analysis: str      # エラーの原因分析
    next_step_suggestions: list[str]  # 具体的な次のステップ提案
    should_continue: bool    # 更なる反復が有望か
```

### 5.5 Exploitation 閉ループフロー

```
iteration = 0
exploit_plan = None
prev_feedback = None

while iteration < MAX_EXPLOITATION_ITERATIONS:
    # 1. Plan
    plan_output = planner.run(vuln, exploit_plan, prev_feedback)
    exploit_plan = plan_output.exploit_plan
    action = plan_output.next_action

    # 2. Validate
    validation = validator.validate(action, exploit_plan)
    if not validation.is_valid:
        prev_feedback = validation.feedback
        iteration += 1
        continue

    # 3. Execute
    exec_result = executor.execute(action)  # Docker sandbox内

    # 4. Evaluate
    eval_result = evaluator.evaluate(exec_result, exploit_plan, vuln)

    if eval_result.status == "success":
        return SUCCESS(evidence=exec_result)
    
    if not eval_result.should_continue:
        return FAILURE(reason="no further progress likely")
    
    prev_feedback = eval_result
    iteration += 1

return FAILURE(reason="max iterations reached")
```

---

## 6. Long-term Memory 仕様

### 6.1 3層メモリ設計

```python
class MemoryItem:
    id: str
    layer: Literal["vulnerability_pattern", "strategy", "technical_action"]
    title: str           # 簡潔な識別子
    description: str     # 1文の要約
    content: str         # 蒸留された知識
    source: Literal["success", "failure"]
    embedding: list[float]  # ベクトル表現
    created_at: datetime
    task_context: str    # 元タスクの文脈
```

**層1: Vulnerability Pattern Memory**
```
格納内容: 確認済み脆弱性スキーマ
  - 観察可能な症状 → 脆弱性仮説 → 確認テスト の進行
  - false leads（確認を妨げた偽のリード）
例: "URL fetch + 特定設定フラグ → SSRF。初期には異なる脆弱性クラスを示唆する誤導指標あり"
用途: Stage I の Analysis Agent が参照。再発パターンの迅速認識。
```

**層2: Strategy Memory**
```
格納内容: 高レベルのエクスプロイト戦略
  - 成功戦略: "設定分析をペイロード作成に先行させる"
  - 失敗パターン: "実行コンテキスト理解なしのブラインドファジングはデッドエンド"
  - ターゲット間で転移可能な一般化教訓
例: "XSS exploitation across distinct web frameworks" の共通戦略
用途: Stage II の Planner Agent が参照。計画策定のガイダンス。
```

**層3: Technical Action Memory**
```
格納内容: 具体的な低レベルアクション
  - 成功: 再利用可能な "how-to" スニペット
  - 失敗: ピットフォールと修正調整
例: "SSRF到達性テスト: curl -v http://target/fetch?url=http://attacker.com/probe"
用途: Stage II の Planner/Execution が参照。trial-and-error削減。
```

### 6.2 メモリ検索

```python
def retrieve(self, query: str, layer: str = None, top_k: int = 3) -> list[MemoryItem]:
    query_embedding = self.embedding_model.encode(query)
    
    candidates = self.vector_db.search(
        query_embedding=query_embedding,
        filter={"layer": layer} if layer else {},
        top_k=top_k,
        metric="cosine"
    )
    
    return candidates

# コサイン類似度: sim(u, v) = (u · v) / (||u|| * ||v||)
```

### 6.3 メモリ合成

```python
def synthesize_memory(self, trajectory, outcome: str, vuln, exploit_plan):
    """
    タスク完了後、軌跡からメモリアイテムを抽出・合成する。
    
    trajectory: 実行トレース全体
    outcome: "success" or "failure"
    """
    # 1. LLM-as-a-judge で軌跡を分類（論文では Evaluation Agent + Orchestrator のシグナル）
    
    # 2. 抽出戦略の適用
    if outcome == "success":
        # 検証済み戦略、有効パターンを抽出
        items = self._extract_success_patterns(trajectory, vuln, exploit_plan)
    else:
        # 反事実的シグナル、ピットフォールを抽出
        items = self._extract_failure_lessons(trajectory, vuln, exploit_plan)
    
    # 3. 各層に適切なメモリアイテムを生成
    for item in items:
        item.embedding = self.embedding_model.encode(item.title + " " + item.description)
        self.vector_db.insert(item)

def _extract_success_patterns(self, trajectory, vuln, plan):
    """LLMを使用して成功軌跡から構造化メモリを抽出"""
    prompt = f"""
    以下の成功したエクスプロイト軌跡を分析し、3層のメモリアイテムを抽出してください:
    
    1. Vulnerability Pattern: 脆弱性の認識パターン（症状 → 仮説 → 確認）
    2. Strategy: 高レベル戦略（何が有効だったか、何を回避すべきか）
    3. Technical Action: 再利用可能な具体的コマンド/スニペット
    
    脆弱性: {vuln}
    計画: {plan}
    軌跡: {trajectory}
    """
    return self.synthesis_llm.generate(prompt)  # gemini-2.5-pro 推奨
```

### 6.4 コールドスタート初期化

```python
def initialize_warm_start(self):
    """CWE Top 25 + 専門家経験からキュレーション済みメモリアイテムを投入"""
    
    cwe_top25_patterns = load_cwe_top25_patterns()  # CWEサイトから事前構築
    expert_strategies = load_expert_strategies()     # 手動キュレーション
    
    for pattern in cwe_top25_patterns:
        self.store(MemoryItem(
            layer="vulnerability_pattern",
            title=pattern.cwe_id,
            description=pattern.name,
            content=pattern.description + "\n" + pattern.exploitation_guidance,
            source="curated"
        ))
    
    for strategy in expert_strategies:
        self.store(MemoryItem(
            layer="strategy",
            ...
        ))
```

---

## 7. ツール定義一覧

### 7.1 コードブラウジングツール（Stage I & II で使用）

| ツール名 | 引数 | 戻り値 | 説明 |
|---------|------|--------|------|
| `get_working_directory_tool` | なし | `str` (パス) | 現在の作業ディレクトリ |
| `get_whole_file_structure_tool` | `code_path: str` | `str` (ツリー) | コードベース全体のファイル階層 |
| `list_directory_tool` | `dir_path: str` | `list[str]` | 指定ディレクトリのファイル一覧 |
| `read_file_tool` | `file_path: str` | `str` (内容) | ファイル全体の読み取り |
| `get_snippet_tool` | `file_path: str, start_line: int, end_line: int` | `str` (コード) | 指定範囲のコードスニペット |
| `read_readme_tool` | `code_path: str` | `str` (内容) | READMEファイルの読み取り |

### 7.2 セキュリティ知識ツール

| ツール名 | 引数 | 戻り値 | 説明 |
|---------|------|--------|------|
| `get_vulnerability_summary` | `cwe_id: str` | `str` (概要) | CWE IDから脆弱性概要を取得 |
| `query_vulnerability_docs` | `query: str` | `list[Document]` (top-3) | 自然言語クエリで脆弱性ドキュメントを検索 |

### 7.3 メモリツール

| ツール名 | 引数 | 戻り値 | 説明 |
|---------|------|--------|------|
| `vulnerability_memory_tool` | `query: str, layer: str = None` | `list[MemoryItem]` (top-3) | メモリからの類似検索 |

### 7.4 実行ツール（Stage II の Execution Agent 専用）

| ツール名 | 引数 | 戻り値 | 説明 |
|---------|------|--------|------|
| `run_bash` | `command: str` | `ExecutionResult` | Docker内でBashコマンド実行 |
| `run_python` | `script: str` | `ExecutionResult` | Docker内でPythonスクリプト実行 |

### 7.5 検証ツール（Planner Agent にツールとして公開）

| ツール名 | 引数 | 戻り値 | 説明 |
|---------|------|--------|------|
| `validate_action` | `action: str, plan: ExploitPlan, state: SystemState` | `ValidationResult` | アクションの事前検証 |

---

## 8. エージェント完全プロンプト

### 8.1 Analysis Agent プロンプト

```
You are a 'Senior Security Analyst Agent' specializing in brainstorming potential
vulnerabilities from code. Your goal is to be creative but grounded in evidence.

**INPUT:**
You will receive:
- 'code_path': A string representing the location of the code to analyze.
- 'memory_context' (optional): pre-retrieved vulnerability memories or lessons learned
  for similar targets. Treat this as initial inspiration.
- 'critic_feedback' (optional): A list of vulnerabilities that were previously proposed
  and the critic's feedback on why they needed refinement.

**YOUR TASK:**
1. **Phase 1: Analysis & Refinement**
   * **If 'critic_feedback' is provided:**
     * Treat this as a "fix-it" task. For every criticized/rejected item, you MUST find
       better evidence (a specific line number) or a stronger risk argument. If you can't,
       discard it.
   * **If 'critic_feedback' is NOT provided (Initial Run):**
     * **Scan:** Use code_browser_tools ('get_whole_file_structure_tool',
       'read_readme_tool', etc) to map the stack. Understand file structures; identify
       entry points (routes, APIs) and configuration files; locate vulnerable and
       suspicious files, etc.
     * **Consult Memory:** Call 'vulnerability_memory_tool' with technical keywords
       (e.g., 'flask deserialization', 'sql injection python'). Use these results to
       guide your search.
     * **Security knowledge collecting:** Consult security database with
       'get_vulnerability_summary' and 'query_vulnerability_docs', to get initial
       inspirations.
     * **Deep Dive:** Apply proper strategies to analyze the code. Use code_browser_tools
       ('get_snippet_tool', etc) to inspect specific high-risk files.

2. **Phase 2: Evidence Compilation**
   For each valid vulnerability, you must construct a rigorous evidence chain:
   * **Source:** Where does the untrusted input enter? (File/Line)
   * **Sink:** Where is it executed/processed dangerously? (File/Line)
   * **Context:** Why is existing protection insufficient?

3. **Phase 3: Output Generation**
   Produce a **'BrainstormOutputSchema' object** containing a list of 'vulnerability'
   records.
   * 'id': Temporary ID (e.g., DRAFT-001).
   * 'class_name': Standard CWE-format name (e.g., "CWE-79: Reflected XSS") or other
     names.
   * 'description': Clear summary of the flaw.
   * 'evidence': The specific file, line number, and code snippet.
   * 'risk_rationale': Why this matters (impact).

**POTENTIAL USEFUL ANALYSIS STRATEGIES:**
Use these specific mental models to guide your search. Do not just "read code"—apply
these lenses:

1. **Taint Analysis (Source-to-Sink):**
   * *Goal:* Find injection flaws (SQLi, RCE, XSS).
   * *Method:* Identify an Entry Point (e.g., 'request.args['id']') and trace it forward.
     Does it hit a Dangerous Sink (e.g., 'cursor.execute', 'eval', 'subprocess.call')
     without sanitization?

2. **Trust Boundary Mapping:**
   * *Goal:* Find authorization/authentication bypasses.
   * *Method:* Identify where data crosses from "Untrusted" (Public Internet) to "Trusted"
     (Internal App). Is there a middleware or check *at that exact boundary*? (e.g., Is
     '@login_required' missing on the '/admin' route?)

3. **Configuration & Dependency Audit:**
   * *Goal:* Find infrastructure flaws.
   * *Method:* Inspect 'Dockerfile', 'docker-compose.yml', 'requirements.txt'. Look for
     debug modes ('DEBUG=True'), hardcoded secrets ('API_KEY=...'), or vulnerable library
     versions.

4. **Business Logic Tracing:**
   * *Goal:* Find IDOR and Workflow bypasses.
   * *Method:* Trace a multi-step user action (e.g., "Reset Password"). Does the server
     rely on client-side state (cookies, hidden fields) to validate the user's identity
     in Step 2?

**NOTE:** These are *core examples* of effective analysis techniques. You are encouraged
to employ other relevant cybersecurity methodologies (e.g., Race Condition testing,
Cryptographic analysis, etc.) as appropriate for the specific codebase.

**CRITICAL RULES:**
- **No Hallucinations:** Do not invent code. Evidence must match the actual file content.
- **Memory Driven:** If you cite a 'memory_context' item, explain *how* it applies to
  this specific codebase.
- **Quality over Quantity:** It is better to return 2 well-proven vulnerabilities than
  10 vague guesses.
- code_browser_tools available: 'get_working_directory_tool',
  'get_whole_file_structure_tool', 'list_directory_tool', 'read_file_tool',
  'get_snippet_tool', 'read_readme_tool'.
- Security knowledge tools available: 'get_vulnerability_summary',
  'query_vulnerability_docs'.
```

### 8.2 Critique Agent プロンプト

```
You are a 'Critic Agent'. Your job is to meticulously review and validate a LIST of
proposed vulnerabilities based on the provided evidence.

**INPUT:**
You will receive an input containing a 'vulnerability_list'.

**YOUR TASK:**
1. Initialize an empty list called 'review_results'.
2. Iterate through each 'vulnerability' object in the input 'vulnerability_list'.
3. For each vulnerability:
   a. Carefully examine its 'description', 'evidence', and 'risk_rationale'.
   b. Use your tools ('code_browser', 'vulnerability_doc') if necessary to verify
      context or get more information.
   c. Assess the feasibility and accuracy. Is the evidence convincing? Is the rationale
      sound? Is this likely a real vulnerability?
   d. Determine an estimated_risk_level (Critical, High, Medium, Low, Informational).
      The definition for each level is as follows:
      * Critical: Exploitation is trivial or highly probable and leads to full system
        compromise, complete loss of sensitive data, or severe financial/operational
        damage. Requires immediate, emergency action.
      * High: Exploitation is highly probable and leads to significant data loss,
        unauthorized elevated access, or major, prolonged service disruption. Requires
        urgent remediation (e.g., within days).
      * Medium: Exploitation is possible, leading to limited data exposure, potential
        denial of service, or moderate system functionality impact. Requires standard
        remediation.
      * Low: Exploitation is difficult or has low impact. Should be remediated when
        resources allow.
      * Informational: A deviation from best practices with no direct exploitable risk.
   e. Assign a review_status: "approved", "rejected", or "needs_refinement".
   f. Provide concrete feedback explaining the decision.
```

### 8.3 Planner / Validation / Execution / Evaluation Agent プロンプト

論文Appendix A.1に概要が記載されているが、完全テキストは上記2エージェントほど詳細に開示されていない。以下は論文の記述から再構成した仕様である。

**Planner Agent（再構成プロンプト要旨）**:
```
あなたはエクスプロイト計画を策定・改訂する専門エージェントです。

入力: 脆弱性記述、証拠チェーン、コードパス、（オプション）既存のExploit Plan、
      前回の実行フィードバック

タスク:
1. Exploit Plan が存在しない場合: Grounding Phase を実行し初期計画を策定
   - 脆弱性記述と証拠チェーンの解釈
   - 脆弱性ドキュメントから関連知識を取得
   - コードベースをスキャンして技術スタックと攻撃面を理解
   - 長期メモリから過去の成功戦略を参照
   - 具体的ステップ列としてExploit Planを策定

2. Exploit Plan が存在する場合: フィードバック駆動の改訂
   - 試行ステップのstatus更新
   - 失敗時: 修正アクション挿入、将来ステップの見直し
   
3. 次の実行アクションを生成し、validate_action ツールで検証してから出力

出力: 更新されたExploit Plan + 次の実行アクション
```

**Evaluation Agent（再構成プロンプト要旨）**:
```
あなたは実行結果を評価する専門エージェントです。

入力: ExecutionResult、現在のExploit Plan、脆弱性記述

タスク:
1. 実行が意図した目標を達成したか判定
2. 逸脱や予期しない挙動を特定
3. 環境/設定エラーを識別
4. 次のステップの具体的提案を生成
5. 更なる反復が有望かどうかを判断

出力: EvaluationResult (status, goal_achieved, deviations, next_step_suggestions,
      should_continue)
```

---

## 9. データスキーマ定義

### 9.1 全スキーマ一覧（Pydantic形式）

```python
from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime

# ===== Stage I =====
class CodeLocation(BaseModel):
    file: str
    line: int
    snippet: str

class Evidence(BaseModel):
    source: CodeLocation
    sink: CodeLocation
    context: str

class VulnerabilityDraft(BaseModel):
    id: str
    class_name: str
    description: str
    evidence: Evidence
    risk_rationale: str

class BrainstormOutputSchema(BaseModel):
    vulnerability_list: list[VulnerabilityDraft]

class CritiqueResult(BaseModel):
    vulnerability_id: str
    status: Literal["approved", "rejected", "needs_refinement"]
    estimated_risk_level: Literal["Critical", "High", "Medium", "Low", "Informational"]
    feedback: str

# ===== Stage II =====
class PlanStep(BaseModel):
    id: int
    goal: str
    action: str
    status: Literal["planned", "in_progress", "done", "blocked"]
    dependencies: list[int] = []
    feedback: str = ""

class ExploitPlan(BaseModel):
    steps: list[PlanStep]
    overall_strategy: str
    current_step_index: int

class ExecutionResult(BaseModel):
    status: Literal["success", "error", "timeout"]
    stdout: str
    stderr: str
    exit_code: int
    execution_time_seconds: float

class ValidationResult(BaseModel):
    is_valid: bool
    checks: dict
    feedback: str

class EvaluationResult(BaseModel):
    status: Literal["success", "partial_progress", "failure", "environment_error"]
    goal_achieved: bool
    deviations: str
    error_analysis: str
    next_step_suggestions: list[str]
    should_continue: bool

# ===== Memory =====
class MemoryItem(BaseModel):
    id: str
    layer: Literal["vulnerability_pattern", "strategy", "technical_action"]
    title: str
    description: str
    content: str
    source: Literal["success", "failure", "curated"]
    embedding: Optional[list[float]] = None
    created_at: datetime
    task_context: str = ""

# ===== Final Output =====
class ExploitEvidence(BaseModel):
    poc_payload: str
    exploit_trace: str
    reproduction_steps: list[str]

class VulnerabilityReportItem(BaseModel):
    vulnerability: VulnerabilityDraft
    critique: CritiqueResult
    exploitation_success: bool
    evidence: Optional[ExploitEvidence]
    exploit_plan: ExploitPlan

class VulnerabilityReport(BaseModel):
    target_code_path: str
    results: list[VulnerabilityReportItem]
    memory_items_generated: int
```

---

## 10. 設定パラメータと推奨値

| パラメータ | 論文での値 | 説明 |
|-----------|-----------|------|
| `max_discovery_iterations` | 3 | Analysis-Critique反復の上限 |
| `max_exploitation_iterations` | 20 | Plan-Execute-Evaluate反復の上限 |
| `memory_top_k` | 3 | メモリ検索の取得件数 |
| `embedding_model` | gemini-embedding-001 | エンベディングモデル |
| `synthesis_llm` | gemini-2.5-pro | メモリ合成用LLM |
| `backbone_llm` | 全エージェント共通 | バックボーンLLM（実験では Gemini-2.5-flash/pro, Gemini-3-pro） |
| `docker_timeout` | 未明示（推定60-120s） | 実行タイムアウト |
| `warm_start_memory` | CWE Top 25 + 専門家経験 | メモリ初期化データ |

---

## 11. 評価ベンチマークと主要結果

### 11.1 ベンチマーク

| ベンチマーク | タスク | 特徴 |
|-------------|--------|------|
| CyBench | Exploitation (CTF) | 40問のプロ級CTFタスク |
| BountyBench | Detect + Exploit | 25システム、40バグバウンティ、OWASP Top 10の9カテゴリカバー |
| CyberGym | Exploitation (PoC) | 大規模現実的、実行可能PoC生成 |

### 11.2 主要結果（Gemini-3-Pro）

| 手法 | CyBench | BountyBench Exploit | BountyBench Detect | CyberGym |
|------|---------|--------------------|--------------------|----------|
| Vanilla | 18.5% | 17.5% | 0.0% | 12.1% |
| OpenHands | 45.2% | 45.0% | 5.0% | 20.2% |
| C-Agent | 47.8% | 47.5% | 5.0% | 21.5% |
| **Co-RedTeam** | **63.7%** | **65.0%** | **20.0%** | **37.3%** |

### 11.3 アブレーション（Gemini-2.5-Pro, CyBench基準）

| 除去コンポーネント | ASR | 低下幅 |
|-------------------|-----|--------|
| Full | 59.1% | — |
| No Execution | 17.5% | ▼41.6pt |
| No Code Browser | 47.5% | ▼11.6pt |
| No Memory | 50.0% | ▼9.1pt |
| No Validation | 52.3% | ▼6.8pt |
| No Vul-doc | 55.2% | ▼3.9pt |

### 11.4 レイテンシ（Gemini-3-Pro, 秒）

| 手法 | CyBench | BountyBench | CyberGym |
|------|---------|-------------|----------|
| Co-RedTeam | 319.8 | 198.7 | 605.2 |
| C-Agent | 320.3 | 201.9 | 611.7 |
| OpenHands | 347.6 | 219.6 | 609.7 |

---

## 12. 数理的背景と設計根拠

### 12.1 Taint Analysisの形式化

プログラムの格子束 L = {untainted, tainted} 上の前方データフロー問題。伝搬規則:
```
taint(f(x₁, x₂)) = tainted  if taint(x₁) = tainted ∨ taint(x₂) = tainted
```
Co-RedTeamではLLMがコードブラウジングツールを通じてこれを「ソフトに」近似実行する。

### 12.2 実行フィードバックの不可欠性（Rice's Theorem）

プログラムの非自明な意味論的性質は一般に決定不能。脆弱性のexploitabilityは実行時挙動に依存する意味論的性質であり、静的解析のみでは判定不能。Co-RedTeamの閉ループ実行は、仮説を環境で直接テストすることでこの理論的限界を回避する。アブレーションで実行除去時 ▼41.6pt は、この原理の定量的裏付け。

### 12.3 Analysis-Critique反復の不動点解釈

```
V₀ = AnalysisAgent(C, memory, ∅)
Fᵢ = CritiqueAgent(Vᵢ)
Vᵢ₊₁ = AnalysisAgent(C, memory, Fᵢ)
```
3反復の上限は経験的に十分であることがアブレーションで確認。

### 12.4 メモリ検索のコサイン類似度

```
sim(u, v) = (u · v) / (||u|| * ||v||)
retrieve(q, M, k) = top-k_{m ∈ M} sim(embed(q), embed(m.title ⊕ m.description))
```

### 12.5 ReasoningBank（先行研究）の原理

Co-RedTeamのメモリ設計の基盤。メモリアイテム m = (title, description, content) を成功/失敗の両軌跡から蒸留。retrieve → inject → judge → distill → append の閉ループ。

---

## 13. 実装ロードマップ

### Phase 1: 基盤構築
```
□ プロジェクト構造の作成
□ データスキーマ（Pydantic モデル）の実装
□ Docker sandbox環境の構築
□ コードブラウジングツール群の実装
□ バックボーンLLMのインターフェース実装
```

### Phase 2: Stage I 実装
```
□ Analysis Agent の実装（プロンプト + ツール接続）
□ Critique Agent の実装
□ Analysis-Critique 反復ループの実装
□ 単体テスト（既知の脆弱性を含むサンプルコードで検証）
```

### Phase 3: Stage II 実装
```
□ Planner Agent の実装（Exploit Plan管理含む）
□ Validation Agent の実装
□ Execution Agent の実装（Docker連携）
□ Evaluation Agent の実装
□ Plan-Execute-Evaluate 閉ループの実装
□ 統合テスト
```

### Phase 4: Memory 実装
```
□ Vector DB のセットアップ
□ Embedding モデルの接続
□ 3層メモリストアの実装
□ メモリ検索ツールの実装
□ メモリ合成パイプラインの実装
□ Warm Start データの準備（CWE Top 25 から）
```

### Phase 5: Orchestrator & 統合
```
□ Orchestrator 状態機械の実装
□ 動的ルーティングロジック
□ エージェント初期化とツール割当
□ 全体統合テスト
□ ベンチマーク評価（CyBench等の利用可能なサブセット）
```

### Phase 6: 最適化
```
□ プロンプトチューニング
□ メモリ進化の検証（逐次タスク処理での性能推移確認）
□ レイテンシ最適化
□ エラーハンドリングの強化
```

---

## 補足: ローカルLLM での実装考慮事項

1. **コンテキストウィンドウ**: Gemini-2.5-proは100万トークン超のコンテキストを持つが、ローカルLLMでは制限が厳しい場合がある。コードブラウジングツールによるオンデマンド読み取り設計がこの制約を緩和する。

2. **ツール使用能力**: Co-RedTeamのエージェントは多数のツールを適切に選択・使用する必要がある。ローカルLLMのtool-use能力がボトルネックになり得る。Qwen3-Coder等のtool-use特化モデルが推奨される。

3. **メモリ合成の品質**: メモリ合成はLLMの要約・抽象化能力に依存する。合成用LLMにはバックボーンと同等以上の能力が望ましい。

4. **Embedding モデル**: gemini-embedding-001の代替として、nomic-embed-text、bge-large等のローカルモデルが使用可能。コサイン類似度検索の精度に影響するため、ドメイン適合性のテストを推奨。

5. **バックボーンLLMのスケーリング効果**: 論文はモデル能力の向上がフレームワーク性能に非線形にスケールすることを示している。Gemini-2.5-flash → 2.5-pro → 3-pro の順に全ベンチマークで性能が向上。ローカルLLMでも最大能力のモデルを使用すべき。

---

*出典: Pengfei He et al., "Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents," arXiv:2602.02164v2, Feb 2026. / Ouyang et al., "ReasoningBank: Scaling Agent Self-Evolving with Reasoning Memory," arXiv:2509.25140, Sep 2025.*
