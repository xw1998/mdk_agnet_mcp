# mdkdebug / MCP 问题台账

> 用途：把**真机调试里实际撞到的**工具问题一条条记下来——现象、机理、影响、处置、
> 现在什么状态。不写成「改进愿望清单」（那是 `docs/swd-trace-improvements.md`），
> 只写**已经发生过的**事。
>
> 一轮调试（2026-09-20，STM32F427 + DAPLink SWD 两线 + Keil UVSOCK@4823）中，
> 用户的一句「感觉不对啊，任务切换怎么这么慢而且只有一次。。。」牵出了下面 11 条
（第 12 条「文案写死端口号」来自同一轮的实测清单，一并记在这里）。
> 环境：环 `mdk_trace_swd_blob` @ `0x200020C8`，ring 8192 B（编译期常量），
> 事件率实测约 5000~6700 条/s。

---

## 一、一眼看完

| # | 类别 | 问题 | 用户/调试者看到的现象 | 状态 |
|---|---|---|---|---|
| 1 | trace 可信度 | **时间轴冻在原点** | 页面报「时长 44 s / 上下文切换 12081」，泳道里只有 1~2 段 | 已修 `562acf1` |
| 2 | trace 口径 | **`events` 是会话尾部，不是本批新增** | 拼出来的「轨迹」是 N 个互相重叠的窗口，同一段时间被数很多遍 | 已修 `562acf1` |
| 3 | trace 性能 | **`limit` 给大反而更容易丢事件** | 前 10 轮不丢、第 11 轮起丢且加速（lost 增量 664→…→5207） | 已修（文档+`only_new`），机制上仍待 `A3` |
| 4 | 工具面 | **`max_session_events` 在 MCP 面上不存在** | 传了直接 `参数名不被接受`（Python 签名里有，工具包装没暴露） | 已修 `44383c9`（真机复核通过 2026-09-20） |
| 5 | 会话建立 | **`reset_connection` 之后直接用 trace 报「没有活着的调试会话」** | 要先随便读一次（预热）才能选到链路；错误信息没给这一步 | 已修 `44383c9`（真机复核通过 2026-09-20） |
| 6 | trace 模式 | **`consistent="run"` 在真机上基本不可用** | 全速读回 `repeated_word` 伪值 → `swd-read-untrusted` | 已缓解（默认转 halt）+ 描述写明实测结论 `44383c9`，模式本身仍不可用 |
| 7 | trace 节拍 | **没有「还能录多久」的预算工具** | 停机一轮 ~0.45~0.67 s、可持续 ~6~9 KB/s，节拍只能自己试 | 已修 `279ff41`（真机复核通过 2026-09-20） |
| 8 | 任务名 | **任务泳道全是裸序号** | 时间轴上只有 0..15，看不出谁在跑 | 已修 `aad0a94` |
| 9 | 任务名 | **跨镜像取名会给出「看着权威的错答案」** | 地址命中就安名字，但板上跑的可能不是那份构建 | 已修 `b080398` |
| 10 | 渲染 | **badge 报「事件 0」，且统计口径写进了绘图口径** | 满屏轨道配一个「事件 0」；文案与事实相反 | 已修 `b080398` |
| 11 | 环境 | **连接器工具面与实际仓库不一致** | 「明明装了却看不到 trace 工具」；部署目录停在旧提交 | 属配置问题，见第四节 |
| 12 | 文案 | **提示里写死的端口号与事实不符** | `serial_expect` 超时提示让人去 `port="COM9"`，而 `available_ports` 里是 COM3；`modbus-no-session` 也照抄示例号 | 已修 `44383c9` |
| 13 | trace 同源 | **环尺寸与符号不同源时会静默错位** | 换了固件/换了 `.axf` 后读环解出一堆看着像事件的垃圾 | 已修 `279ff41`（`C1` 交叉校验） |

---

## 二、核心：trace 数据可信度

### 1. 时间轴冻在原点（最严重，属「看得见的错答案」）

**现象**：页面出来了、徽章也对（时长 44 s / 上下文切换 12081 / 中断进出 60294），
时间轴画成一条平平的、有刻度的轴。用户一眼看出不对：**「任务切换怎么这么慢而且
只有一次。。。」**——泳道里只有一两段，事件全挤在原点。

**机理**（在**设备侧**，不在渲染侧）：
`kernelsrc/components/mdk_trace/mdk_trace_swd.c::mdk_trace_swd_event()`

```c
now = SWD_NOW();
dt  = now - s_last_cycles;
s_last_cycles = now;
...
} else if (c->dt_unit != 0u) {
    dt = dt / c->dt_unit;      /* 整数除法：余数丢掉，且不累加到下一次 */
}
```

余数既**丢掉**又**不累加**。粒度比事件间隔粗时每条都算出 0；`dt == 0` 走 HITN 分支，
**只写 1 字节、根本不写 dt**，宿主读回来就是 0。宿主把 dt 当「与上一条的时间差」累加，
时间轴便永远停在原地。

**实测**（F427，事件平均间隔约 150~200 µs）：

| 粒度 | `dt_unit` | `dt == 0` 占比 | 时间轴 |
|---|---|---|---|
| `500us` | 48000 | **100%** | 冻结 |
| `10us` | 960 | ~70%（同一 10 µs 桶内的事件为 0） | **真实**（13.542 s） |
| `1us` | 96 | 0% | 真实 |
| `cycle` | 0 | 0% | 真实 |

> **`dt == 0` 本身不等于冻结**，它只表示「与上一条落在同一个量化桶里」；
> 判据是「**本批全都**是 0」。

**影响**：这是最坏的一类——**结构正确、数值全错**。页面会正常渲染、徽章会给出
像模像样的数字，不报错、不空白，看图的人会把「冻在原点」读成「这段时间没有调度」。

**处置**：宿主侧主动报出来，而不是照画。

- `trace_swd_read` 新增 `time_axis_frozen` 检测（本批 `dt` 全 0 且样本 ≥ 200 条）
  与 warning，说清机理并**指向换细粒度重录**；
- `viz` 的「时间轴」badge 冻结时报**「冻结」（level=bad）**，并在 limits 里补说明；
- 回归用例：`tests/test_batch64.py` I1~I3、`tests/test_viz.py` B8d。

### 2. `events` 是会话尾部，不是本批新增

**现象**：第一版采集脚本写的是 `events.extend(out["events"])`，20 轮下来存了
**78454** 条——看着很壮观，其实那 20 轮每轮都返回「会话最后 4000 条」，
拼起来是 **20 个互相重叠的窗口**，同一段时间被数了很多遍。第一版网页就是基于它做的。

**机理**：工具返回的 `events` = `_swd_session_view(s, limit)["events"]`，是**整个会话**
的尾部最多 `limit` 条；`new_events` 才是**本批**条数。而工具描述当时写的是
「每次它只搬走新增的那一段」——**文案与实现相反**，正好把人带进沟里。

**影响**：离线回放/统计全错（重复计数），而且很难自己发现，因为条数、顺序都「像」。

**处置**：
- 新增显式开关 **`only_new=true`**：`events` 只给本批新增的 `new_events` 条；
- 新增 `events_scope` 字段（`session` / `new`）把口径写在返回里；
- 工具描述 + docstring + README + SKILL 全部改成「默认给会话尾部（含前几次调用、
  会重叠），要拼线性轨迹必须传 `only_new`」；
- 回归用例：`tests/test_batch64.py` J1~J3、G3。

### 3. `limit` 给大反而更容易丢事件

**现象**：同一台板、同一个粒度（10 µs）、同样 24 轮，只差 `limit`：

| `limit` | `lost` 增量 | 备注 |
|---|---|---|
| `200000` | **+33570** | 前 10 轮不丢，第 11 轮起丢且**加速** |
| `7000` | **+2299** | 集中在第 1 轮，之后逐轮恒定 |

**机理**：`limit` 是「返回会话最后多少条」，给到 20 万时，**每轮都要把整个会话
序列化成 JSON 喂回来**（第 19 轮时那是 11 万条），单次调用越来越慢 → 环在这段时间里
被写满 → 开始丢。而丢事件会触发设备侧的**正反馈**：

> 丢一条 ⇒ 目标 `swd_dict_clear()` ⇒ 下一条必是 LIT（5+ 字节）⇒ 更快填满 ⇒ 丢更多

实测 lost 增量 `664 → 721 → 1538 → 2345 → 3161 → 5207`。所以
**「搬运循环慢一点点」的代价是指数级的丢**。

**处置**：`only_new` + 文档写明「`limit` 压到刚好盖住本批」。
机制上的正解仍是 `A3`（把节拍/预算交给工具算）。

### 4. `max_session_events` 在 MCP 工具面上不存在

**现象**：`trace_swd_read(max_session_events=20000)` 直接报
`参数名不被接受：max_session_events。trace_swd_read 接受的参数：addr、consistent、elf、granularity、limit、link、names、out_file、reset_session、tasks`。

**机理**：`trace.py::swd_read()` 的 Python 签名里有 `max_session_events`
（默认 `_SWD_MAX_SESSION_EVENTS`），但 `@server.tool` 包装的
`async def trace_swd_read(...)` **没有把它接出来**。两层签名不一致，
调用方从工具描述里看不到这个能力，看到了也传不进去。

**影响**：想限制会话内存/单轮开销的人（就是本节第 3 条的解法之一）无从下手，
只能改用「压小 `limit`」这个间接办法。**属于「修复手段不在默认工具面上」的同类问题。**

**状态**：**已修 `44383c9`**。`trace_swd_read` 的 `@server.tool` 包装把
`max_session_events` 接出来（默认即 `_SWD_MAX_SESSION_EVENTS`）并透传给
`swd_read()`，描述里同时写明「这是会话内存上限，与 `limit`（返回条数）是两件事，
压 `limit` 只治标」。回归用例 `tests/test_batch65.py` B 组钉住「包装签名里有、
能透传、描述里提了」。

**真机复核（2026-09-20，F427 + SVCRTOS_TEST）**：默认面（core，42 个工具）里
`trace_swd_read` **不在面上**，调用报 `Unknown tool`——那是第 12 条的配置问题，不是本条。
`toolset(action="load", toolsets="trace")` 之后工具数 42→76，`inputSchema` 的
`properties` 里出现 `max_session_events`（`{"default": 500000, "type": "integer"}`）；
真机带 `max_session_events=100000` 调一次被正常接受并返回事件（不再报「参数名不被接受」）。

### 5. `reset_connection` 之后直接用 trace 工具会报「没有活着的调试会话」

**现象**：按下述顺序调用

```
set_symbol_file → reset_connection → trace_swd_reset
```

`trace_swd_reset` 报
`swd-read-failed：两个链路都没有活着的调试会话，无法读目标内存`；
而紧接着的 4 次 `trace_swd_read` 全部失败。**但 `keil_health` 报
`Keil 与 UVSOCK 均就绪`、`read_mem` 也正常。**

**机理**：`reset_connection` 之后链路是**惰性重建**的，需要先有一次真实的读写
把链路选出来；`trace_swd_reset` 内部的 `_link.pick()` 走的是「活着的会话」判据，
在预热之前拿不到链路，于是连坐报错。加一次任意读（`read_mem`）之后，同样的
调用序列立刻正常。

**影响**：用户/Agent 会以为「设备掉了」而去查硬件、查 Keil、重启调试会话——
**排查方向被带偏**。而且这个错误信息**没有给出下一步**（「先做一次读」）。

**状态**：**已修 `44383c9`**。修法选的是「自动建链」而不是「报错里加 hint」：
`linkio` 新增 `keil_client(prepare=True)`，统一「先主动把 UVSOCK 连上」——
`_try_keil` 与 `rtos` / `rtrace` 三处此前各写一份，漏掉一处就会复发（batch50 修过
`rtrace`，这次轮到其余两处）。主动建链只开 TCP + 握手，**不进调试、不 halt、
不碰目标**，与其余工具首次调用时的行为一致。
`reset_connection` 的返回文案也一并改成「下次调用会**自动重新建立**（不必先做一次
读来预热）」。回归用例见 `tests/test_batch65.py` A 组。

**真机复核（2026-09-20，F427 + SVCRTOS_TEST，UVSOCK@4823）**：与 `171d2d3`（修复前）
在同样状态下做对照——

| 步骤 | `171d2d3`（修复前） | `3ba2feb`（修复后） |
| --- | --- | --- |
| `reset_connection` 后 `phy.is_connected` | `False` | `False` |
| **紧接着第一次**调用 `trace_swd_read`（不做任何预热读） | `swd-read-failed：两个链路都没有活着的调试会话，无法读目标内存`，之后仍是 `False`（没建链） | 日志 `已连接到 UVSOCK @ 127.0.0.1:4823` → `ok:true`，`new_events=2466`，`is_connected` 变 `True` |
| 事件内容 | — | `counts_by_type` 为 `gap:9 / isr:1889 / sched:378 / event:190`；`sched` 事件带真名（`svcrt_shell_task → idle`）；blob 由 `elf_symbol` 定位到 `0x200020C8` |

即「不预热直接 trace」从「报错并把人带去查硬件」变成「静默建链后正常读到事件」。
（附带一条当时踩到的现象：目标**全速运行**时读控制块会整片回 `0x00`，工具如实报
`swd-read-degenerate` 而不是当成「没有事件」；`halt` 后再读即 2466 条——与第 6 条同一族。)

### 6. `consistent="run"` 在真机上基本不可用

**现象**：`consistent="run"`（全速读，不停机）在有数据时稳定报
`swd-read-untrusted：全速运行时搬回的这段字节是伪值（repeated_word，共 8191 字节）`。

**机理**：目标在跑，SWD 读 RAM 与目标写环并发 → 读到退化字节。设备侧 `tokens`
自证可以定性（停机读 `tokens == 目标 tokens`，运行态读 `tokens < 目标 tokens`）。

**影响**：`run` / `auto` 这两个选项在被测目标上**形同虚设**；好在 `A1` 已把默认
改成 `halt`，所以默认路径不受影响。但它仍然出现在工具描述里作为「可选」，
读者会以为能用。

**状态**：**已缓解**（默认 halt + 伪值拦截 `43c07c0`），并在工具描述里写明实测结论
（`44383c9`）：「实测（F427 + DAPLink）：`run` 稳定报 `swd-read-untrusted`，
要用就先按 `halt` 走」。模式本身没修——它取决于目标侧「运行态读 SRAM 是否可靠」，
不是宿主能绕开的。

### 7. 没有「还能录多久」的预算工具，节拍只能自己试

**现象**：停机搬运一轮 **halt 0.45~0.67 s**、整轮 0.9~1.4 s；环只有 8192 B。
于是「多密的节拍才不丢」只能靠反复试错——本次就是这么试出来的
（`0.30 s` 也不行、`0.05 s` 在 10 µs 粒度下刚好）。

**机理**：`trace_swd_status` 只报**已经丢了多少**，不报**还能录多久**
（建议中的 `A3`：`window_ms` / `suggest_pace_ms` / `headroom_bytes`）。

**状态**：**已修**（`279ff41`，工具 `trace_swd_next`）。

修法：读两次控制块（间隔 `sample_ms`，默认 300），用 `head` 的差值测**真实**写入速率，
再除剩余环空间 → `window_ms`（还能录多久）、`suggest_pace_ms`（＝窗口 ÷ 安全系数 8）、
`headroom_bytes` / `headroom_events` / `bytes_per_event_now` / `batch_estimate`。
只读：不搬字节、不动游标、不停机。速率是**测出来的**——目标这段时间一个字节都没写就
返回 `window_ms=null` 并说明「测不出」（绝不拿容量除一个猜的事件率）。

**真机上顺手撞到的第三类错答案（方向错）**：环用到 `>= 3/4` 时，目标被**背压**憋住
（写不进新字节、正在丢事件），`head` 一动不动——旧文案把它说成「目标没在跑」，
而目标其实跑得好好的。现在用 `stalled` 字段区分三种情形并各自给下一步：

| stalled | 什么时候 | 说的是什么 |
|---|---|---|
| `ring-full` | `pending == cap` | 环满了，目标此刻每条都在丢，先搬一次再谈节拍（`window_ms=0`） |
| `ring-nearly-full` | 环用到 `>= 3/4` 且 `head` 不动 | 很可能是背压；先搬一次，搬完又立刻涨满就是背压（该调粗粒度 / 少插桩 / 改大环），一直不动才是没在跑 |
| `no-writes` | 环还空着却没写 | 真的测不出窗口（没在跑 / 没插桩 / 录完了），这不是「窗口无限大」 |

另一处：窗口算出来不到 1 ms 时（真机量到过剩余 1 B、窗口 0.09 ms），旧代码会给一个
`suggest_pace_ms = 10`——比窗口本身还大，等于教人按必然丢事件的节拍走；现在直说
「没有可调的节拍，先搬一次」。

**F427 真机结论（2026-09-20）**：环 8192 B + 实测事件率约 3.2k 条/s、3.34 B/条
→ 环只够 2.4 s 上下的余量，而单轮 `halt` 搬运就要 ~0.54 s；只要宿主不是一直在搬，
`pending` 就长期贴在 8191/8192（本次会话 `lost_events` 已累积到 1000 万+）。
工具如实报的就是这个结论：`stalled=ring-full` / `round_budget.ok=false`，
并在单轮成本 ≥ 建议节拍时明说「环太小 / 事件太密，按这个节拍也追不上」。

---

## 三、任务名与符号

### 8. 任务泳道全是裸序号（已修）

流里 `sched` 事件只带 4 bit 任务号（`0..14` 任务表下标、`0xF`=idle）。旧版
`names` 只映射「事件 id」，**没有**任何把任务号翻成名字的途径，于是时间轴上
只有数字——用户原话：「里面没有任务的 trace 很差劲」。

修法（`aad0a94`）：读内核 `svcrt_task_table[i].entry`（`void (*)(void)`，
偏移从 DWARF 取），拿入口地址反查 ELF 函数符号；`tasks=auto` 在会话内解析一次，
**解析成功后历史事件也回头重补名字**（否则前半段还是数字，看起来像「任务只在
后半段出现」）。

### 9. 跨镜像取名会给出「看着权威的错答案」（已修）

**现象**：把 app/驱动的 `.axf` 一起传进来，希望跨镜像的入口也拿到名字——
但地址精确匹配只证明「该地址在**那份**构建里是函数首地址」，
**不证明板上跑的就是那份构建**。

**修法**（`b080398`）：跨镜像名字必须过**内容核对**（读板上该地址若干字节，
与 `.axf` 同地址字节比）；核过记 `sym_verified="content-confirmed"`，
**核不过 / 核不了 → 丢名**并记 `unconfirmed_slots`、并入 `unmapped_slots`、
`partial=True`；任一路径不存在 → `tasks-elf-missing` 并点名。

F427 实测：4 个槽位拿到名字，3 个跨镜像槽位如实留空（它们的入口在 example 下 5 份
`.axf` 里**都不是函数首地址**——那几个镜像当时确实不在这些构建里）。产出就是
照旧 `ctx3/ctx4/ctx6` + 说明怎么补名字，**不编一个像样的名字**。

顺带：`0xF` 既是 idle 任务号又是异常号（两个命名空间），旧代码会把中断轨道
标成任务名；已隔离。

### 10. IRQ 号仍是裸号（部分）——已修（`279ff41`）

实测出现 17 / 5 / 4 号 IRQ 无法命名，中断轨道全是裸号。

修法（`C3`）：纯主机侧读**镜像的向量表**（`.isr_vector` 段，或 `__Vectors` 符号所在段），
表项 index == 异常号，只覆盖**异常号 >= 16** 的外设段（0~15 是内核异常，另有异常名表）。
`trace_swd_read` 返回里多出 `irq_names` / `irq_names_note`，viz 的中断轨道优先用真名。

两条守卫是拿**两枚真实 `.axf`** 实测后加的（不加就是「看着权威的错答案」）：

1. **表尾之后是代码字节**。MDK 把整块 ROM 合成一个段、`__Vectors` 的 `st_size` 只有 4，
   按「段尾」当表尾会一路读进代码，解析出 3439 → `__scatterload_copy` 这种假名。
   现在设上界 256，且读到「非 0 又不是任何函数首地址」就收手。
2. **同址多符号**。链接器把一堆空的 `*_IRQHandler` 折成同一段代码（本仓 F427 工程里
   同一地址挂着 **87 个** STT_FUNC 符号），按名字取会给出 `ADC_IRQHandler` 这种错名。
   现在 `len(names) != 1` 一律留空，并在 `irq_names_note` 里说明「那个地址挂着多个处理
   函数名，分不清是哪一个」。

复验：F427 内核 `.axf` → `{53: USART1_IRQHandler}`，`mdk_test.axf` → `{54: USART2_IRQHandler}`。

**真机这一条只走得到「如实留空」**：本固件（F427 / SVCrtOS）的插桩点只有内核异常
（实测流里只有 11 = SVC、14 = PendSV），**没有外设 IRQ 的插桩**——控制台收发确实在跑
（发 `help` 有响应），但流里没有 USART1 的 53 号，所以那时返回 `irq_names=null` +
`irq_names_note` 点名「11, 14 是内核异常号」。这是**固件没插桩**，不是工具查不到；
正路径由两枚真实 `.axf` 的离线反查覆盖（`tests/test_batch66.py` D 组）。

---

## 四、渲染（viz）与环境

### 11. badge 报「事件 0」，且统计口径写进了绘图口径（已修）

时间线适配层用 `len(evs) * thinned` 报事件条数：没抽稀时 `thinned = 0`，
于是**满屏轨道配一个「事件 0」**；真抽稀时它又只是估算（8 条报成 10 条）。
同一处的 `limits` 文案还写着「统计口径仍是全量」，而 sched/fault 计数其实是在
**抽稀后**的子集上数的——文案与事实相反。

修法（`b080398`）：抽稀**前**先把真值留下来（`total_events`），badge 报总数、
类型计数一律走全量事件列表；文案改成「每 N 条抽 1 条**绘制**（总数与下面的计数
仍是全量）」。回归用例同时钉住两头（`test_viz` B8b/B8c）。

### 12. 连接器工具面与实际仓库不一致（环境，属配置）

**现象**：真机调试期间，MCP 连接器只暴露 **42** 个工具，`trace_*` 组**根本不在面上**——
「明明装了却看不到工具」。而同一份仓库代码进程内启动（`toolsets="all"`）时有 **190** 个。

**成因**（两类，都碰到过）：
1. **工具面是分组的**，默认只暴露常用组；`trace` / `ocd` / `coverage` 等要显式开
   （`--toolsets` 或参数）。
2. **连接器进程是用旧代码启动的**：仓库更新后必须重启连接器才会重新注册新工具
   （本次也因此改为在仓库代码里**进程内直连 UVSOCK** 做真机验证）。

**现状**：连接器 `ez3mjx` 的 command 已指向仓库目录
（`cd "/d/工作/git_project/mdk_agent" && … run_server.py --idle-timeout 30 …`），
但**默认面仍是 42 个工具**；跑全功能验证要在启动参数里显式开全组。

> 附：这一条也解释了为什么「工具改了但用户看不到」——**面和代码是两件事**，
> 报错与文档里说「去调它」之前，要先确认它在不在当前工具面上。

---

## 五、文案与事实不符（同一轮实测里撞到的两处，已修 `44383c9`）

**这两处的共同点**：工具本意是「帮你下一步怎么走」，写的内容却是**过期的示例值**——
照着做会走到错的地方。比没有提示更糟。

1. **串口提示里写死的端口号**。`serial_expect` 超时后的 `next_actions` 让人去
   `port="COM9"`，而同一次返回里的 `available_ports` 明明是 COM3。
   修法：`serialmon._port_hint()` 优先写**本机真实端口**——有 `list_ports()` 真值
   就用真值，没探测到就不编。`read_lines` / `write_bytes` 共用它。
2. **`modbus-no-session` 照抄示例号**。知识库里的示例端口（COM9）被当成建议透出。
   修法：去掉写死的号，改成「口以 `serial_list_ports` 的结果为准，别照抄示例号」。

回归用例：`tests/test_batch65.py` C 组（文案不再出现写死端口）、D 组（有真值时
提示必须用真值、无真值时不冒充事实）。

## 六、仍未修的（照实列）

| # | 未修项 | 影响 | 备注 |
|---|---|---|---|
| — | 外设 IRQ **名字**取决于固件有没有插桩（`C3`） | 本固件只插桩内核异常，所以外设 IRQ 连长什么样都看不到 | 机制已就绪（`279ff41`）；要看到 53 → `USART1_IRQHandler`，得先在固件里插桩那一路 |
| — | 停机搬运 ~0.48~0.67 s/轮 | 吞吐 ~6~9 KB/s，环 8192 B 是硬约束（实测环只够 2.4 s 上下） | `C1` 交叉校验已做（`279ff41`）；「环运行期可配」受固件定长数组限制，要改固件重编重烧 |

---

## 七、本轮相关提交

| 提交 | 内容 |
|---|---|
| `43c07c0` | trace(swd)：运行态读 SRAM 伪值拦截 + 停机一致搬运 |
| `aad0a94` | 调度事件带上任务名（跨镜像入口留空不编名） |
| `b080398` | 多份镜像联合取名（跨镜像名字要过内容核对）+ viz 计数口径修正 |
| `1ae523b` | 批次67：链路↔符号对照（`uvsock_binding` / `binding-mismatch` / 两个符号工具上移 core）+ `BK *` 后 FPB 校验（`hardware` / `fpb` / `breakpoint-residue`）+ 复位循环三态（`reset_loop` / `rapid`） |
| `279ff41` | 批次66：节拍预算 `trace_swd_next`（`A3`）+ 中断名反查（`C3`）+ 环尺寸交叉校验（`C1`）；含真机撞到的「背压被说成没在跑」「建议节拍比窗口还大」两处文案修正 |
| `562acf1` | 时间轴冻结要报出来 + `events` 口径开关（`only_new`） |
| `44383c9` | 台账 #4/#5 真缺陷修复（`max_session_events` 接出、链路选择层主动建链）+ 两处文案纠偏 |

相关文档：`docs/swd-trace-improvements.md`（改进清单与实测数据）、
`docs/PITFALLS.md` 第二十六 / 二十七 / 二十八条。

---

## 八、批次67：另一个 AI 的 H7 + J-Link 反馈（2026-09-20）

来源：用户转述另一 AI 在 H7 + J-Link + Modbus 现场的复盘。它列的「最有价值的三件事」是：
`set_symbol_file` 暴露出来、`BK *` 后校验 J-Link 硬件断点寄存器、检测「同一断点短时间反复命中」
并提示可能是复位循环。三条的共同点是——**MCP 给的信号本身诚实**（`firmware-mismatch`、
`degenerate` 都触发了），但「错误符号绑定 + 断点残留 + 缓存脏读」叠在一起会掩盖真相。

| # | 现象（对方现场） | 机理 | 处置 | 状态 |
|---|---|---|---|---|
| 1 | 4823 被一个加载 `mdk_test` 的旧 Keil 实例占着；重开正确工程后 `get_status` 仍报 `symbol_file: mdk_test.axf` + `firmware-mismatch`，符号解析全落在错误镜像上（假符号 `usart.c:143`、裸地址下断点 error 57） | 链路与符号**可能来自不同实例**，而工具面没有「这条链路是谁的」这一事实；`set_symbol_file` 又在默认收起的 `symbol` 组——看到了问题也切不了符号 | ① `get_status.uvsock_binding`：4823 的监听者 PID / 窗口标题 / 工程路径（`GetExtendedTcpTable`，取不到留空并说明「无法对照」，不拿符号文件名顶替）；② `_binding_state` 把「链路工程 ↔ 符号工程」不一致报成 `binding-mismatch`（带例外条款：调 App 时不一致本就正常）；③ `set_symbol_file` / `list_symbol_projects` 上移到 `core`（默认面 42→44）——教训页「修复手段不在默认工具面上」的最终落点 | 已修 · 真机复核通过（4823 → PID 22508 → `SVCRTOS_TEST.uvprojx`） |
| 2 | `BK *` 清不干净，J-Link 反复报 "two breakpoints at the same address"，后续断点状态全被污染 | Keil 的 `BK *` 只清**逻辑**表，清不掉调试器留在 FPB 里的硬件比较器 | `list_breakpoints.hardware` / `clear_all_breakpoints(hard=True).fpb`：读 `FP_CTRL` + `FP_COMPn`；有启用的比较器 → `check=residue` + `error_code=breakpoint-residue` + **`ok=false`**（否则「已清干净」是假象），并给与 Keil 逻辑表的差集 `orphans`；**读不到一律 `unavailable`**（没测 ≠ 没有） | 已修 · 真机复核通过（`0x00000260`、0 启用 → `clean`） |
| 3 | `stat_flow_init` 断点「再次命中」其实是复位循环在重跑启动，被当成正常命中，多绕一圈 | 「短时间反复命中」没有专门的信号，而现成的 `repeat_warning` 语义**恰好相反**（疑似 halt 残留值、别当反复复位看） | `wait_breakpoint.reset_loop` + `breakpoint_stats.rapid`：窗口 3 s 内命中 ≥3 次才判定；有复位证据（命中 Reset_Handler / SP == 向量表初始 SP / CYCCNT 回退）→ `suspected=true` 并给下一步；只是反复命中 → **`null`**（主机侧分不清复位循环与正常热循环）并附人工核对手段 | 已修 · 真机只复核到「未命中 / 未判定」路径（见下） |

**真机复核（2026-09-20，F427 + DAPLink，Keil PID 22508 = `SVCRTOS_TEST`）**：

- `uvsock_binding`：`state=bound`、`owner_pid=22508`、`owner_project=…\SVCRTOS_TEST.uvprojx`；
  本会话未加载符号时如实报 `symbol_file=null` + note「无法与链路工程对照」，**不拿链路工程名顶替**。
- FPB：`FP_CTRL=0x00000260`（连读两次一致）、全部比较器条目为 0 → `check=clean`、`enabled_addrs=[]`；
  `clear_all_breakpoints(hard=True)` 复核仍 `clean` 且 `ok=true`；**退出调试后 FPB 不可读 → `unavailable`**（不是 clean）。
- 槽位口径：真机 `NUM_CODE=6 / NUM_LIT=2`，按「字段 = 个数 - 1」得 7 代码 / 3 字面量，而 F4 的 FPB
  通常记作 6 代码 + 2 字面量——两个口径差 1。故槽位数只当**推导值**给，新增 `counts_note` 声明口径与
  不确定性（不把推导值说成权威结论；判残留只看 `enabled` 位）。
- `rapid`：`hist_len=0` / `rapid_addrs=[]` / `checked={}`，如实报「窗口内无命中」。
- **未复核**：`reset_loop.suspected=true` 那条路径——没在真机上制造复位循环，也没抢到一次真命中
  （`wait_breakpoint` 5 s 超时）。此路目前只由 mock（`tests/test_batch67.py` F 组）覆盖，
  **别把它当「真机验证通过」**。
- 真机小观察（只记录，未改动）：一次 `wait_breakpoint` 超时后紧跟的 `exit_debug` 返回 `ok=false`
  （`error` 为空），补一次 `stop` 后 `exit_debug` 成功——怀疑与「目标仍在运行态时退调试」有关，尚未定位。

回归用例：`tests/test_batch67.py`（89 项）；`tests/test_batch61.py` 改写为「默认面已可见 → 不再前置装卸，
装卸分支由裁剪面（`MDKDEBUG_TOOLSETS=mem`）覆盖，坑的形状没变」。

---

## 批次74 · 工具面瘦身三刀（2026-09-26）

**背景**：AI 反馈「工具规模太大，不利于上下文与注意力机制」。实测默认面（core 44 个工具）
一次 tools/list 的 JSON 为 89,079 字节，其中 description 占 66%、inputSchema 18%（内含递归
`title` 3,327 字节）、outputSchema 6.3%、annotations 5.2%。三刀合计：core 89,079→39,458（默认档
同时从 `full` 改 `lean`；只算结构刀是 89,079→63,996，−28.2%）；all 413,796→200,598；nano
25,998→14,968。

| 刀 | 内容 | 关键事实 |
|---|---|---|
| 一 | 结构瘦身（`mdkdebug/surface.py`，只改 wire 副本） | `tool.output_schema` 在 **FastMCP 的活 Tool** 上是只读 property，读 `fn_metadata.output_schema`；而那个字段在**调用路径**上决定「要不要把返回值包成 structuredContent」（`func_metadata.py`: `output_model = self.output_model if self.output_schema is not None else None`）。直接置 None 会**真的改返回形态**——「看似权威的错答案」。`MCPServer.list_tools()` 每次新造 MCPTool（wire 副本），`mcp/shared/peer.py` 序列化用 `exclude_none=True`，所以只对副本置 None 即从线上消失、行为零变化。逃生口 `MDKDEBUG_SURFACE=off` |
| 二 | 默认描述档 `full`→`lean`（`thin.DEFAULT_MODE` / `toolbox.desc_default_for`） | **对批次56 口径的显式反转**（批次56：默认 full，理由是「默认档悄悄砍边界条件容易用错工具」；批次74：AI 反馈规模本身伤注意力，lean 保住【输出控制】/【参数】/【调用示例】与结尾告警，`MDKDEBUG_DESC=full` 整面逐字节还原）。nano 档仍自动 `min` |
| 三 | 取回指针瘦身（~82→~69 字符） | 收益小（core 约 374 字符），主要为了别让指针自己成为长文 |

**放弃的刀**：删描述里的【参数】块——core 面合计仅 6,038 字符、真冗余（与 inputSchema 重复）
仅 1,464 字节，且与批次33「schema 里有的参数、描述里必须有说明」的口径冲突。

**test_batch64 顺带修复**：F1 原断言硬编码 `TCB_SIZE=76 / ENTRY_OFF=64`（某次 F427 Debug 实测值，
固件一改即过期，且与当前 axf 实测 156/140 不符已现红）。改为「结构不变量 + 测试内独立
pyelftools 走查交叉核对」，魔数改名 `MOCK_TCB_SIZE/MOCK_ENTRY_OFF`（仅 mock 自造表用）。

回归用例：`tests/test_batch74.py`（24 项，含 `MDKDEBUG_SURFACE=off` 的 A/B 逐字段对照）；
`tests/test_batch56.py` C1/C3/C6/C8 断言同步改为 lean（87 项）。
