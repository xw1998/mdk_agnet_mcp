# 编译 · 烧录 · 调试上板使用指南

> 面向使用 mdkdebug 的 AI 与开发者：说清「改完代码要上板跑一遍」这件事里，
> 编译、烧录、进调试各自做了什么、哪些步骤必须、哪些其实可以省。
> 核心结论：**Keil 进入调试时通常会自动把最新程序烧进 Flash**，所以"先烧录再调试"多数时候是重复劳动。

---

## 1. 一句话结论

Keil 的 `Options for Target → Utilities` 页勾选 **Update Target before Debugging**（Keil 默认勾选）时，
**进入调试前 Keil 会自动把最新程序下载进目标 Flash**——等价一次烧录。
因此「编译 → 直接进调试」就够了，不必「编译 → 烧录 → 再进调试」。

反过来说：**`enter_debug` 是一个有烧录副作用的操作**，它不只是"挂上调试器"，还可能改写目标 Flash。
若工程没有勾选该选项，进调试时 Keil 不会下载，板上可能仍是旧固件。

---

## 2. 机制：点 Debug 时到底发生了什么

```
编译（UV4 -b / -r）  ──►  mdk_test.axf 更新
        │
        ▼
enter_debug（UV_DBG_ENTER）
        │
        ├─ Keil 读工程选项 Utilities/Flash1/UpdateFlashBeforeDebugging
        │
        ├─ =1 ─► 自动执行 Flash Download（擦除 / 编程 / 校验） ──► 新固件上板
        │
        └─ =0 ─► 跳过下载，直接挂调试器 ──► 板上仍是旧固件（若有）
        │
        ▼
调试器就绪（约 0.6~2.3s，mdkdebug 已自动轮询等待）
```

工程侧对应关系：

| 层面 | 位置 | 取值 |
|------|------|------|
| Keil 界面 | Options for Target → Utilities → Settings（Flash Download 区）→ Update Target before Debugging | 勾选 / 未勾选 |
| 工程文件 | `.uvprojx` → `Utilities/Flash1/UpdateFlashBeforeDebugging` | `1` / `0` |
| mdkdebug 工具 | `read_project_config` 返回的 `update_flash_before_debugging` | `true` / `false` / `null`（工程未写该节点） |
| 默认值 | Keil 新建工程 | **勾选（=1）** |

---

## 3. 我要做的事 → 该调哪个工具

| 你的目标 | 推荐调用 | 说明 |
|---------|---------|------|
| 改完代码，要上板调试（最常用） | `flash_debug` | 「关旧 Keil → 新固件上板 → 重开工程 → 进调试」一体闭环，自动决定要不要显式烧录，规避"旧窗口调试旧代码" |
| 改完代码，只要板子上跑起来（不需要调试） | `build_and_flash` | 编译成功后才烧录；日志集中返回 |
| 固件没变，只想再次进入调试 | `enter_debug` | 目标已在调试态时返回 `already_in_debug=true`，不会报失败 |
| 只要编译（不烧录、不调试） | `build_project` / `rebuild_project` | `-b` 增量 / `-r` 全量 |
| 只要烧录（不调试） | `flash_download` | 显式 `UV4 -f`；工程勾选自动下载时它仍可用，只是 `flash_debug` 里会跳过它 |
| Keil 会话脏了 / 连不上 | `reset_connection` → `restart_keil` | 先轻量复位连接，无效再重启 Keil |

> 编译 / 烧录工具均以**隐藏窗口**后台执行，不会闪现新的 Keil 界面；`launch_uvision` 才是可见方式打开 Keil。

---

## 4. `flash_debug` 的自动选路

### 4.1 执行顺序

```
1. close_uvision(force=False)     关闭所有 Keil 实例（避免残留旧工程窗口 → 调试到旧代码）
2. 让新固件上板（自动选路，见 4.2）
3. launch_uvision                 以可见方式重新打开本工程
4. enter_debug                    进入调试（对连接类错误最多重试 8 次，每次间隔 1s）
```

### 4.2 选路规则

| 工程 `update_flash_before_debugging` | 第 2 步实际做什么 | 返回的 `flash_plan` |
|--------------------------------------|------------------|-------------------|
| `true`（勾选，Keil 默认） | **只编译**，靠 Keil 进调试时自动下载（省掉一次全片擦写 + 一次 `UV4 -f` 往返） | `debug_download` |
| `false` / `null`（未勾选） | **编译 + 显式烧录**（`UV4 -f`），确保板上一定是新固件 | `explicit_flash` |

两条路径都保证「进入调试时跑的是本次编译出来的新固件」；只是上板动作由谁执行不同。

### 4.3 返回字段

| 字段 | 含义 |
|------|------|
| `ok` | 整体是否成功（进调试成功才算成功） |
| `stage` | `调试` 表示走完全程；失败时是 `编译` 或 `编译烧录` |
| `flash_plan` | `debug_download`（Keil 自动下载）/ `explicit_flash`（显式烧录） |
| `flash_note` | 本次上板方式的自然语言说明 |
| `build` | 编译结果（`ok` / `exit_code` / `status_text` / `output` 等）；**编译失败提前返回时该字段名为 `build_flash`** |
| `flash` | 显式烧录结果；走 `debug_download` 时为 `null` |
| `launch_uvision` | 拉起 Keil 的结果（PID 等） |
| `enter_debug` | 进入调试的结果（`ready` / `ready_waited_ms`） |
| `close_uvision` | 第 1 步关闭旧 Keil 实例的结果 |
| `status_text` | 收尾文案 |

### 4.4 失败时的行为

编译没通过就**不烧录、不重开工程、不进调试**，直接返回：

```json
{
  "ok": false,
  "action": "flash_debug",
  "stage": "编译",
  "flash_plan": "debug_download",
  "build_flash": { "ok": false, "exit_code": 2, "output": "...(编译错误)..." },
  "status_text": "编译未通过，未重开工程进入调试"
}
```

> `exit_code` 语义：`0` 成功、`1` 成功但有警告、`2` 有错误、`>=3` 构建不完整。
> mdkdebug 判定 `ok = exit_code in (0, 1)`；编译错误可用 `parse_build_errors` 解析成结构化列表。

---

## 5. 典型调用序列

### 5.1 AI 改代码后上板验证（推荐）

```
flash_debug(project=".../mdk_test.uvprojx")     # 编译 → 新固件上板 → 重开 → 进调试
  → set_breakpoint(expr="main")
  → run  →  wait_breakpoint(symbol="main")      # 注意：先 run 再 wait
  → read_variable(name="test_array")
  → exit_debug
```

### 5.2 只想让板子跑起来看现象

```
build_and_flash(project=".../mdk_test.uvprojx")
  → exit_debug（若当前在调试态；调试是 halt 式的，挂停时外设现象会停滞）
```

### 5.3 固件没变，只是想再进调试

```
enter_debug()      # 已在调试态则返回 already_in_debug=true，不会报错
```

---

## 6. 常见问题

**Q1：我没有显式烧录，为什么板子上是新程序？**
因为工程勾选了 Update Target before Debugging，Keil 在进调试前自己下载了。
这正是 `flash_plan=debug_download` 的含义；`flash_note` 里也会写明"本次未显式烧录"。

**Q2：怎么确认我的工程到底是哪种？**
调用 `read_project_config`，看 `update_flash_before_debugging`：

- `true` → 进调试会自动下载；
- `false` → 不会，必须显式烧录；
- `null` → 工程文件里没有该节点（老工程/非 Keil 生成），**按"不会自动下载"处理**，别假设它会烧。

**Q3：怎么改这个选项？**
Keil 界面：Options for Target → Utilities → Settings → 勾选/取消 Update Target before Debugging。
改完保存工程即可，mdkdebug 每次都实时读 `.uvprojx`，无需重启。

**Q4：我只想烧录，不想进调试怎么办？**
用 `flash_download`，它不会改变调试态。

**Q5：会不会因为残留旧 Keil 窗口而调试到旧代码？**
`flash_debug` 的第一步就是关闭所有 Keil 实例，之后才编译/上板/重开，从机制上规避；
这也是它比你手工"先 build 再点 Debug"更稳的地方。

**Q6：`launch_uvision` 之后马上 `enter_debug` 报连接失败？**
UVSOCK 就绪需要数秒（真机实测约 3s）。`flash_debug` 内部对连接类错误最多重试 8 次；
手工分步调用时应先轮询 `keil_health` 直到 `uvsock_ready=true`，或直接用 `restart_keil`（自带等待与重连）。

**Q7：编译时 Keil 处于调试态可以吗？**
建议先 `exit_debug` 再编译/烧录，调试态下编译可能失败。

---

## 7. 注意事项与边界

- **烧录会覆盖目标 Flash**，属有副作用操作；请确认接的是目标板而非他人的板子。
- **`enter_debug` 有烧录副作用**（工程勾选自动下载时），工具描述中已如实标注。
- **调试是 halt 式的**：只要保持调试连接，目标要么被挂起、要么被断点拦停，LED / 串口现象会停滞。
  要观察真实运行现象，请在 `run` 之后不再 stop/读内存，或 `exit_debug` 让目标自由运行。
- 编译 / 烧录自带**调试通道自愈**：执行前取一次 4823 健康快照，执行后再取一次，
  仅在"编译前可用、编译后不可用"时自动重启 Keil 并重建连接（真机实测约 3.7s 完成）。
  用户本就没开 Keil 时不会擅自拉起；可用 `ensure_debug_channel=false` 关闭。
- `.uvoptx` 会携带上次会话的**持久化断点 / 数据观察点**，进入调试时被 Keil 自动恢复，
  可能干扰"运行到 main"之类的预期（真机曾因此停在 scatter 拷贝例程 `!!handler_copy`）。
  排查时用 `list_breakpoints` 看 `real` 字段，必要时 `clear_all_breakpoints(hard=true)` /
  `clear_all_watchpoints(hard=true)` 清空。

---

## 8. 真机验证记录（2026-09-17）

环境：STM32F401 例程 `example_mdk_project/mdk_test`，UVSOCK@4823，编译器 AC5 V5.06 update 7。

| 项目 | 结果 |
|------|------|
| 工程选项 | `update_flash_before_debugging = true` |
| `build_project` | `exit_code=0`，0 Error(s), 0 Warning(s) |
| `rebuild_project` | `exit_code=0` |
| `flash_download` | `Erase Done. Programming Done. Verify OK.` |
| `build_and_flash` | 编译成功 → 烧录成功 |
| `flash_debug` | `ok=true`、`stage=调试`、`flash_plan=debug_download`、`flash=null`、`enter_debug.ready=true`（`ready_waited_ms≈2218`），即**未显式烧录**，由 Keil 进调试时自动下载 |
| `launch_uvision` / `close_uvision` / `restart_keil` | 全部通过；重新拉起后 UVSOCK 约 3s 就绪 |
