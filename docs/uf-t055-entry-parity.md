# 交付说明：库入口 / 命令行入口检出口径统一（uf-t055）

## 1. 问题现象

同一份秘钥样本，分别经两个入口扫描，报出的命中不一致：

- 库入口：`default_settings()` + `SecretsCollection.scan_file(...)`
- 命令行入口：`detect-secrets scan <file>`（验收口径加 `--no-verify`）

在修复前的快照（`d37e268`）上，实测分歧有两处：

1. **CLI 静默吞掉真实命中。** CLI 默认注册验证策略过滤器
   `detect_secrets.filters.common.is_ignored_due_to_verification_policies`，
   其判定为 `verify_result.value < min_level.value` 即丢弃。默认 `min_level=UNVERIFIED(2)`，
   于是 `VERIFIED_FALSE(1)` 的命中（已泄露后被吊销的凭证，例如样本中的 AWS Access Key）
   被静默过滤；库入口根本不注册该过滤器，同一命中照常报出。
2. **一种真实秘钥两个入口都漏报。** `GitHubTokenDetector` 的经典 token 正则用了
   **捕获分组** `(ghp|gho|ghu|ghs|ghr)_[...]{36}`，`re.findall` 只回传分组内容，
   导致命中的秘钥值被截断成 `ghp` 这类前缀（写入基线的哈希也是前缀的哈希）；
   同时细粒度 PAT（`github_pat_<22位>_<59位>`）完全没有对应规则，两个入口都检不出。

## 2. 统一方案与路线选择

总原则：**以库入口的检出口径为基准，让 CLI 向库入口对齐，而不是反过来收紧库入口。**
任务硬约束是"统一后命令行入口不得漏报库入口能报出的命中"，因此任何让库入口少报的
路线都不可接受。

### 修复 A：验证策略过滤器只在严格策略下生效（`detect_secrets/filters/common.py`）

- 只有 `--only-verified`（`min_level == VERIFIED_TRUE`）才允许压制命中：
  验证为真的保留，其余（验证为假、无法验证）过滤。
- 默认策略（`UNVERIFIED`）与宽松策略一律不丢弃任何命中，函数直接返回 `False`，
  与库入口"不注册该过滤器"的可观测结果一致。
- 网络异常时保守处理：无法验证 ≠ 判定为假，不丢弃（保持原代码对
  `RequestException` 的容错意图，只是不再把异常折算成 `UNVERIFIED` 后参与比较）。
- 过滤器本身、`min_level` 配置项、`--no-verify` / `--only-verified` 两个开关全部保留，
  没有删除任何既有机制，只改了默认策略的语义。

### 修复 B：GitHub Token 正则（`detect_secrets/plugins/github_token.py`）

- 经典 token 分组改为**非捕获分组** `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`，
  提取值从前缀变为完整 token，基线哈希随之正确。
- 新增细粒度 PAT 规则 `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`
  （GitHub 官方格式：固定前缀 + 22 位字母数字 + `_` + 59 位字母数字）。

## 3. 牺牲了什么（副作用与取舍）

1. **默认 CLI 扫描会多出"验证为假"的命中。** 这是有意的口径放宽：这类凭证曾经有效、
   属于真实秘钥，漏报的风险高于多报。adhoc `--string` 模式下它们显示为
   `False (verified)` 而不是旧的 `False`，即从"静默消失"改为"明示验证为假"。
   若巡检只想要验证为真的秘钥，显式加 `--only-verified` 即可恢复严格行为。
2. **经典 GitHub token 的基线哈希会变化。** 旧哈希只覆盖 `ghp` 等 3 字符前缀，
   修复后覆盖完整 token。已有基线中若存在 GitHub Token 条目，重新扫描后该行会表现为
   变更（旧哈希条目录入的本就是错误值）。本仓库自带 `.secrets.baseline` 与 `test_data`
   中没有任何 GitHub Token 样本，故本仓库基线不受影响。
3. 细粒度 PAT 规则采用固定长度的官方格式，不匹配长度不符的伪造串（测试中以短尾串
   固化了这一行为），宁可漏报异形串也不放宽为易误报的模糊匹配。
4. 验证为假时仍会产生一次网络验证调用（默认口径下），`--no-verify` 可完全关闭；
   验收矩阵统一按 `--no-verify` 断网口径执行，不产生任何网络请求。

## 4. 既有防误报机制的交代

没有任何过滤器被删除或静默停用。修复后默认仍注册的过滤器与修复前完全一致：

- 文件名级：`is_invalid_file`、`is_non_text_file`、`is_lock_file`、`is_swagger_file`
- 行级：`is_line_allowlisted`（`pragma: allowlist secret` 豁免）、
  `should_exclude_line`（`--exclude-lines`）
- 秘钥级启发式：`is_sequential_string`、`is_potential_uuid`、`is_likely_id_string`、
  `is_templated_secret`、`is_prefixed_with_dollar_sign`、`is_indirect_reference`、
  `is_not_alphanumeric_string`、`should_exclude_secret`（`--exclude-secrets`）
- 可选组件：gibberish / wordlist 过滤器的注册路径未动
- 验证策略过滤器：**保留注册、保留配置、保留开关**，仅默认策略不再吞命中；
  `--only-verified` 的严格防误报能力原样保留

### 关于 gibberish 过滤器的口径差异（既有设计，不在本次修复内拆除）

`gibberish-detector` 是可选依赖：安装后 CLI 扫描会默认注册
`detect_secrets.filters.gibberish.should_exclude_secret`，而库入口的
`default_settings()` 不注册任何可选过滤器。因此在安装了该组件的环境里直接对比两个
入口，CLI 会少掉被 gibberish 模型判为"非乱码"的命中（实测样本中的两个 AWS 命中即被
此过滤器排除，属防误报行为而非静默吞秘钥的缺陷）。验收探测脚本与本仓库一致性矩阵
沿用既有测试惯例（`testing.mocks.disable_gibberish_filter`）将其关闭后比对，
`--no-verify` 口径下两边检出集合完全一致。该过滤器可通过
`--disable-filter detect_secrets.filters.gibberish.should_exclude_secret` 显式关闭，
本次修复没有改动它的任何逻辑。

## 5. 测试与验收

新增/修改的用例（最小集合，每条都对应一个被修复的缺口）：

- `tests/core/entry_parity_test.py`（新增）：断网口径一致性矩阵，CLI 一律以
  `--no-verify` 运行，与 `default_settings()` 库入口比对
  （文件名/类型/行号/哈希四元组集合），并单向断言 CLI 不得少于库入口；
  另含 AWS key 不被吞、两种 GitHub token 格式双入口均检出、完整 token 哈希三条回归用例。
- `tests/plugins/github_token_test.py`：新增细粒度 PAT 正反例与"提取完整秘钥值"断言。
- `tests/filters/common_filter_test.py`：新增默认策略保留 `VERIFIED_FALSE`、
  `--only-verified` 严格压制、网络异常不丢命中的契约测试。

全套件结果：`1050 passed, 6 xfailed`（Windows 原生 Python 3.12，仓库本地 `.venv`，
`pytest==7.4.3`，`PYTHONUTF8=1`）。

环境说明（仅影响本地测试工具链，不属于仓库代码改动）：

- pytest 8 无法收集仓库内两个 yield 风格测试文件（`tests/plugins/base_test.py`、
  `tests/plugins/keyword_test.py`），故 venv 内固定 `pytest==7.4.3`；未改动全局环境。
- `unidiff==1.0.1` 与本代码库不兼容（`TestScanDiff` 两个用例在 pristine 快照上即失败，
  与本次修复无关），venv 内固定 `unidiff==0.7.4` 后通过。
- 无 `PYTHONUTF8=1` 时存在两个与本次改动无关的既有失败（GBK 区域设置下
  `test_data/config.md` 被当作不可解码文件跳过）。
