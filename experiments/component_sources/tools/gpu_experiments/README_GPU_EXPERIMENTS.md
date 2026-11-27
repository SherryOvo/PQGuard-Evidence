# PQGuard GPU 实验包

**目的**：跑完三项需要 GPU 的实验——**R2**（服务区间内的审计埋点）、**R7b**（7B 稳态配对重复）、**R8a/R8b**（准入成本分解与准入期可用性）。

**不需要 A800。** 7B bf16 权重约 15 GB，任何 ≥24 GB 显存的卡都可以，RTX 5090（32 GB）足够。只有复现 29.55 GB 的 14B 配置才需要 80 GB 卡，而那项在论文范围之外。

---

## 0. 自检（在花 GPU 时间之前先跑这个）

**不需要 GPU、不需要模型、不需要 torch：**

```bash
python3 gpu_serving_benchmark.py --self-test        # 埋点计数、块结构、配对统计、JSON
python3 gpu_admission_benchmark.py --artifacts /任意/本地/目录 --trials 1 \
    --admission-ms 800 --request-rate 40 --availability-trials 1 --out /tmp/smoke
```

第一项在本机已跑通（15/15 通过）。第二项会真实探测端口，也应正常产出 JSON。**两项都通过再上 GPU。**

若要在 GPU 上先做一次极小的端到端冒烟（几秒）：

```bash
python3 gpu_serving_benchmark.py --model Qwen/Qwen2.5-7B-Instruct \
    --blocks 2 --warmup 1 --max-new-tokens 4 --out /tmp/smoke
```

## 1. 环境

```bash
bash setup_gpu_env.sh          # 建 venv，钉 torch 2.5.1+cu124 / transformers 4.57.6
source ~/pqguard-gpu-venv/bin/activate
```

其余脚本只依赖标准库。

## 2. 实验 A — R2：服务区间内的审计埋点（**优先级最高**）

**要回答的问题**：保存的 A800 记录里，full 模式的延迟分布是单峰的（中位 1188.2 ms，p99 1235.4 ms），**容不下**一条 17–20 ms 的每请求签名成分。所以论文目前**不能**声称逐条签名落在 GPU 计量区间内，已按保守分支写入。

**本实验用埋点把它测清楚**：记录每块的签名数、flush 数与 checkpoint 数，以及触发 flush 的请求的延迟分布。

```bash
python3 gpu_serving_benchmark.py \
    --model Qwen/Qwen2.5-7B-Instruct \
    --blocks 100 --warmup 5 --max-new-tokens 64 \
    --audit-schedule per-record --audit-batch-size 10 \
    --out results_r2
```

**判读**：

| 观测 | 含义 | 论文动作 |
|---|---|---|
| `signatures ≈ runs`（full 模式记录数） | 逐条签名确实在区间内 | 可恢复强版本 R1：相对开销的分子含签名 |
| `signatures` 远小于记录数，或为 0 | 签名不在区间内 | 保持保守分支；`audit_instrumentation` 作为佐证 |

输出里的 `audit_instrumentation` 与每块的 `audit_signatures` / `audit_flushes` 就是判据。

## 3. 实验 B — R7b：7B 稳态配对重复

**要回答的问题**：Table S4 每格只有**单次测量序列、无离散度**，而 0.34–1.27% 的区间被写进了摘要。需要配对不确定性。

```bash
python3 gpu_serving_benchmark.py \
    --model Qwen/Qwen2.5-7B-Instruct \
    --blocks 100 --warmup 5 --audit-schedule batched --audit-batch-size 1000 \
    --out results_r7b
```

- 100 个随机完全区组，块内三种模式（plain / transport / full）**随机排序**，排除前 5 块热身；
- 输出 10,000 次块 bootstrap 的配对差异与 95% CI，格式与现有 `*_interleaved_raw.json` 一致；
- `--audit-schedule batched` 可同时得到**批量签名调度**下的稳态数字，用于 §6.6。

**顺带要查的一个疑点**：现有数据里 A800 上 Qwen2.5-7B plain p50 = **1176 ms**，而 RTX 5090 上同一模型 = **903.6 ms**；同为 7B 的 Qwen1.5-7B 在 A800 上却是 **2510 ms**。同机同类模型差 **2.1 倍**，论文只归因于"背景波动、驱动、共享资源、存储缓存"，**没有解释**。若在 5090 上重跑，请**同时**跑 Qwen1.5-7B 与 Qwen2.5-7B 以复现或推翻该差异——这是审稿人很可能追问的点。

## 4. 实验 C — R8a 成本分解 + R8b 准入可用性

```bash
python3 gpu_admission_benchmark.py \
    --model Qwen/Qwen2.5-7B-Instruct \
    --trials 5 --admission-ms 30000 --request-rate 20 --availability-trials 3 \
    --out results_r8
```

**R8a**：把 `T_hash` 拆成"读"与"摘要"两项——冷读一次（含存储读取）、页缓存内再读一次（摘要受限）。两者的速率差就是存储贡献。需要 `sudo` 才能 `drop_caches`；没有 root 时会如实报告 `caches_dropped=false`，**此时两个数字不可解释为分离结果**。

**R8b**：真实可达性探测——子进程绑定端口、完成准入工作、只在准入结束后才开始 accept；父进程在**准入窗口内**按固定速率发起真实连接并记录被拒比例。`serve_previous_model` 分支模拟滚动更新（旧模型继续服务）。失败是**观测到的**，不是假设的。

## 5. 回收结果

```bash
tar czf pqguard_gpu_results_$(date +%Y%m%d).tgz results_r2 results_r7b results_r8
```

把 tarball 发回来，我负责：写入论文、更新 Table S4 的离散度、按判读表决定 R2 的表述、以及把 §6.6 的批量调度数字换成 GPU 侧结果。

## 6. 环境记录（务必保留）

```bash
nvidia-smi -q > results_env_nvidia_smi.txt
python -c "import torch,transformers;print(torch.__version__,transformers.__version__)" \
    > results_env_versions.txt
```

论文 §7.1 要求保留硬件记录与版本清单；换平台跑就必须记下来，否则新数字无法与保存的证据对齐。

## 7. 已在本机验证过的部分（无需 GPU）

| 组件 | 验证 |
|---|---|
| `--self-test`（15 项） | 埋点计数、块内模式齐备且顺序随机、汇总、配对差异精确、JSON 往返 **全部通过** ✅ |
| `AuditInstrument` 计数 | 逐条调度 25 条 → **25 签名**、flush 在第 10/20 条；批量调度 → **2 签名** ✅ |
| `paired_difference` + bootstrap | 构造差 9.0 ms → 实测 **9.000 ms** ✅ |
| R8a 成本分解 | 37.7 MB 假工件 → 读+摘要 1736 MB/s、仅摘要 2335 MB/s、存储占比 25.7% ✅ |
| R8b 可达性探测 | 准入期不服务旧模型 → **拒绝率 1.000**；服务旧模型 → **0.000** ✅ |

**本机无法验证的部分**：真实模型的 `from_pretrained` 与 `generate` 调用路径（本机无 torch）。该路径与保存的 A800/5090 实验使用相同的 API，但**首次在该 GPU 机器上运行时请先跑上面的小冒烟**确认。
