# uf-t055 交付说明：CLI / 库入口检出口径统一

## 问题

同一个扫描引擎，两个入口对同一份样本给出不同结果：

- **库入口**（`detect_secrets.settings.default_settings()` + `SecretsCollection`）不报
  验证过滤器，所有插件命中都会出现在结果里。
- **CLI 入口**（`detect-secrets scan`）默认注册
  `detect_secrets.filters.common.is_ignored_due_to_verification_policies`，
  `min_level=UNVERIFIED(2)`。旧实现用 `verify_result.value < policy.value` 判定，
  于是 `VERIFIED_FALSE(1)` 的命中（典型场景：泄露后已被吊销、verify 接口明确返回
  无效的凭据）被**静默丢弃**。这类命中恰恰是巡检最该看到的真实泄露。

同根因的第二个缺口在 `GitHubTokenDetector`：经典 token 正则用了**捕获组**
`(ghp|gho|...)`，而 `RegexBasedDetector.analyze_string` 走 `re.findall`——有捕获组时
返回的是组内容而非整个匹配，于是落库的"秘钥值"只剩 `ghp` 三个字符；且细粒度 PAT
（`github_pat_...`）完全没有对应的模式，两边入口都漏报。

## 路线选择

选了**收窄过滤器职责**这条路线，而不是给库入口也装上验证过滤器：

1. `detect_secrets/filters/common.py::is_ignored_due_to_verification_policies`
   - 默认策略（`min_level=UNVERIFIED`）下**不过滤任何命中**，直接返回 `False`；
   - 只有显式 `--only-verified`（`min_level=VERIFIED_TRUE`）时才过滤，且只放行
     `VERIFIED_TRUE`；
   - `verify` 抛 `RequestException`（断网、超时）时一律保留命中——网络故障不包含
     任何关于秘钥真假的信息，不能成为静默吞掉它的理由。
   - `min_level` 的注册值保持 `UNVERIFIED` 不变：过滤器的**注册状态**同时被
     `plugins/base.py::analyze_line`（决定是否执行 verify、打 `is_verified` 标）和
     `format_scan_result`（决定输出标签）消费，不能动。
2. `detect_secrets/plugins/github_token.py`
   - 经典模式改非捕获组 `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`，整个 token 才是
     秘钥值；
   - 新增细粒度 PAT 模式 `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`（官方格式：
     前缀 + 22 位字母数字 + `_` + 59 位字母数字）。

备选路线（给 `default_settings()` 也注册验证过滤器、让库入口向 CLI 看齐）被否决：
它会改变所有库用户的默认行为，且默认策略下验证结果依赖网络可用性，库调用会变得更
慢、更不确定。让 CLI 默认向"不静默丢命中"看齐，两入口自然收敛到同一套口径。

## 牺牲 / 权衡

- **默认策略下 `VERIFIED_FALSE` 现在会被报告**（adhoc `--string` 输出
  `False (verified)`，基线中对应条目照常出现）。这是有意为之：被吊销的泄露凭据仍是
  泄露。想只看当前有效的秘钥，用 `--only-verified`，语义不变。
- **`--only-verified` 下网络错误不再丢弃命中**：旧行为是"验证不了就当没有"，新行为
  是"验证不了就如实报出（unverified）"。严格模式下断网时结果会变多，而不是变少。
- 基线中 GitHub Token 条目的 `hashed_secret` 会变（哈希对象从 `ghp` 变成整个
  token），旧基线里已有的 GitHub Token 条目需要重新扫描刷新——这本来就是旧值错误
  的代价。

## 防误报机制的交代

仓库既有的防误报机制**一个都没有删除或削弱**：

- `filters/heuristic.py` 全部启发式过滤器（sequential/uuid/id-string/templated/
  dollar-sign/indirect-reference/lock-file/not-alphanumeric/swagger）、
  `filters/allowlist.py`、`filters/regex.py`、`filters/wordlist.py`、
  `filters/gibberish.py` 均未改动；
- 验证过滤器本身仍然注册、仍然执行 verify、仍然打标，只是默认策略下不再丢弃命中；
  `--only-verified` 的严格过滤能力完整保留；
- 唯一的行为变化是"默认策略不再吞掉 `VERIFIED_FALSE`"和"网络错误不再吞掉命中"，
  两者都属于把**被误吞的真命中**找回来，不是放开误报。

需要说明的一个既有现象（非本次改动引入）：安装了可选依赖 `gibberish-detector` 时，
真实 CLI 默认多注册一个 `should_exclude_secret` gibberish 过滤器，而
`default_settings()` 库入口不注册——这是上游既有的不对称。一致性矩阵测试用
`testing.mocks.disable_gibberish_filter` 把它关掉再比较；真实 CLI 如需与库入口完全
对齐，可加 `--disable-filter detect_secrets.filters.gibberish.should_exclude_secret`。

## 验证（断网口径，CLI 以 `--no-verify` 运行）

- 新增 `tests/core/entry_parity_test.py`：构造含 AWS / GitHub（经典 + 细粒度 PAT）/
  Slack 等命中的样本，分别走库入口与 CLI 入口（`scan --no-verify`），比较
  `(type, line_number, hashed_secret)` 三元组集合，断言 **CLI ⊇ 库**且两集合相等；
  并断言两个 GitHub token 都端到端命中。
- 扩充 `tests/filters/common_filter_test.py`：默认策略保留 `VERIFIED_FALSE`、
  `--only-verified` 过滤 `VERIFIED_FALSE`/`UNVERIFIED`、两种策略下网络错误都不丢命中。
- 扩充 `tests/plugins/github_token_test.py`：五种经典前缀 + 细粒度 PAT 的整个 token
  才是秘钥值；PAT 前缀不完整时不报。
- 以上新增用例在未修复的源码上均失败（已用 stash 源码的方式逐条验证），修复后通过。
- 既有测试套件全量通过（Windows 原生 Python 3.12，源码安装；运行口径见下）。

## 环境口径

- `.venv`（stdlib venv）+ `pip install -e . pytest==7.4.3 responses unidiff==0.7.4
  gibberish-detector pyahocorasick`；pytest 8 无法收集本仓库 yield 风格测试，
  `unidiff==1.0.1` 会让 `TestScanDiff` 在**未改动源码**上同样失败（既有问题），故锁定。
- 全量测试需 `PYTHONUTF8=1`（GBK 区域设置下 `test_data/config.md` 无法解码，
  既有问题）。
