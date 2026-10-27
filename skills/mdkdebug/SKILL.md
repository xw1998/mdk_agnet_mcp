---
name: mdkdebug
description: 用 mdkdebug MCP 驱动 Keil uVision 做在线调试——读变量/内存、断点与运行控制、编译烧录、串口日志、SVD 寄存器解码、工程文件受控编辑。当用户提到 Keil、MDK、uVision、UVSOCK、单步/断点/看变量、烧录固件、Cortex-M 在线调试时使用。
---

# mdkdebug —— Keil 在线调试的组合拳

mdkdebug 是一个把 Keil uVision 变成「可被 AI 调用」的 MCP 服务，共 215 个工具。
本技能告诉你**先调什么、按什么顺序调、遇到问题找谁**，避免在近百个工具里瞎试。

## 零、怎么把它起来（含宿主环境隔离）

**优先用随附启动脚本**：`run_server.cmd`（Windows）/ `run_server.sh`（其余）。
它会先清掉 `PYTHONPATH` / `PYTHONHOME` 等变量，再 `python -E -s` 起服务。

配置 MCP 客户端时，`command` **直接指向启动脚本**（`"command": ".../run_server.cmd"`），
不要写成 `"command": "python"` + `"args": [".../run_server.py"]`——后者的清理时机在 python
起来之后，而崩溃发生在之前。宿主只接受可执行文件时，把 `-E -s -u` 写进 `args`。

为什么不能只靠 `python run_server.py`：宿主（编辑器、Agent 框架）常把自己的 `PYTHONPATH`
传给子进程，指到另一套标准库时，python 会在**解释器初始化阶段**就崩
（`Fatal Python error: init_import_site ... SRE module mismatch`），此时项目代码一行都没执行，
**进程内无法自愈**。进程内的 `bootstrap` 只兜第二档（起来了但 import 到别人的模块 → 清变量重启）。
排错时想禁止自愈（要看到真实崩溃栈）就设 `MDKDEBUG_NO_REEXEC=1`。

## 一、动手前的四条纪律

1. **冷启动先对齐环境**，不要凭印象直接下命令：
   - `capabilities` —— 有哪些通道可用（UVSOCK / UV4 命令行 / SVD / 串口 / 构建），当前工程与符号状态；
   - `list_tools(keyword=...)` —— 复杂工具的参数名不统一（`query/expr/addr/n_bytes`），
     这里有必填参数 + `example_args`，照抄即可；
   - `mdk_guide` —— 典型工作流与常见坑的入口。
2. **不可逆操作先确认目标**：`flash_download` / `build_and_flash` / `write_mem` /
   `close_uvision` / `restart_keil` 这类工具的返回体会带 `risk` 字段；动手前核对
   工程路径、符号文件、目标器件是否就是用户要的那一份。
3. **读到可疑数据不要急着下结论**：整帧 0、`UsageFault` 置位、读值与预期不符时，
   先看返回体里的 `note` / `next_actions` / `cache_info`，再复读一次或复位后对比。
4. **Keil 只开一个窗口，且「先改文件、后开 Keil」**——顺序反了会自己把通道堵死：
   - 正确顺序：`改源码/改工程 → launch_uvision → 调试 → close_uvision`。**先开 Keil 再改文件**
     会让 Keil 弹「文件已被外部修改」的**模态框**，模态框会把 UVSOCK 通道一起堵住
     （后续命令全超时，表现成「调试通道假死」）。
   - `launch_uvision` 默认 `single=true`：已经开着**别的工程**的窗口时**直接拒绝**
     （`error_code=keil-multiple-instances`，返回既有实例与下一步），不代替你关窗口；
     已有**同工程**窗口则强制复用（`reuse_forced=true`）。确实要同时开多个窗口才传 `single=false`。
   - `uvprojx_edit` 在 Keil 开着同一工程时同样会被拦下（`project-open-in-keil`）：先
     `close_uvision` 再改，或显式 `force=true`（不推荐，Keil 里那份仍是旧内容）。
   - 收窗口用 `close_uvision(keep="oldest")`：**持 UVSOCK 4823 的是最早那个实例**，
     别按「留最新」关。

### 逆向产物是**证据**，不是源码（硬规则，批次101）

- `recover_project` / `recover_project_exact` 出的 `src/pseudo_c.c` 带着 `EVIDENCE ONLY` 头注释和
  `#error` 编译期闸门（不定义 `MDKDEBUG_ALLOW_EVIDENCE_ONLY` 就编不过），`report.json` /
  `manifest.json` 里是 `evidence_only: true`。
- **不要**把它挂进工程、也不要挪进 `App/` `Core/` `Src/` `Drivers/` 这类目录：出件入口会直接拒
  （`error_code=evidence-in-build-dir`）。真源码要人按证据重写，混合工程会变成谁也分不清的 `Ported/`。
- 证据产物放独立目录（`<工程>/recovered/` 或源码树之外）。

### 地址类参数怎么传（批次101）

`base` / `flash_start` / `flash_size` / `ram_start` / `ram_size` **十进制和 `0x…` 都收**
（`0b…`/`0o…` 也收；`08000000` 按十进制解释，要十六进制请写 `0x`）。
`image_inspect` 的返回把两个基址分开：`file_offset_base(_hex)` 是**文件里的偏移**，
`load_base(_hex)` 是**加载/烧录地址**（`address_basis` 说明取自 `flash_start` / `param_base` /
`hex_record` / `elf_paddr`），`base_hex` 是 `load_base_hex` 的别名。
导出物一律**无 BOM 的 UTF-8**（CSV 首列就是 `addr`），别再用 `utf-8-sig` 去读。

### 工程管理文件编辑纪律（硬规则，批次97）

`.uvprojx` / `.uvoptx` 是 uVision 的**字节契约**：编码、BOM、行尾都是内容的一部分。
真实事故不止一起——AI 用「读文本 → 改一行 → 写回文本」改工程文件，写回时把 CRLF 换成 LF、
或把编不出的字符写成 `?`，结果 uVision 打开工程报错/分组丢失。这类损坏**在编辑器里看不出来**，
只能在字节层面查。

**BOM 是「打不开」而不是「无害差异」**（批次100 真机事实）：带 `UTF-8 BOM` 的 `.uvprojx`
uVision **读不进去**，命令行构建只回 `exit 15`（`error reading the project file`），
GUI 里就是打不开，且不给更具体的提示。所以 `project_file_check` 把 BOM 判成 `error`，
`uvprojx_edit` 写回时会**顺手去掉 UTF-8 BOM**（结果里报 `bom_stripped`）——
这不是格式漂移，是修复。UTF-16 的工程文件本服务拒绝写（去 BOM 等于改编码，需先转码）。

**必须照做：**

1. **改工程只用 `uvprojx_edit`**（`add_include_path` / `del_include_path` / `add_files` /
   `remove_files` / `add_defines` / `del_defines` / `set_debug_information`）。它内部依次做：
   往返校验（`old_text` 编回去必须逐字节等于磁盘）→ 原编码严格编码（编不出就报
   `encode-failed`，**绝不写成 `?`**）→ XML 可解析校验 → 原子写 → 写后回读核对
   （返回 `verify="byte-identical"`）。任一条不过就**不落盘**。
2. **改前先拿到格式基线**（`encoding` / `bom` / `newline` / `sha256`）：
   `project_file_check` 一次看整个工程（含同名 `.uvoptx`）；`uvprojx_read` /
   `read_project_config` / `list_uvoptx_breakpoints` 的返回值里也**自带 `file_format`**，
   读配置时顺手就有了，不用多跑一趟。**改完再核对**：`sha256` 应该变，
   `encoding` / `newline` 必须**没变**（格式坏了会带 `file_format_warning`）；
   `bom` 是唯一例外：带 BOM 的文件写完 BOM 会消失，那是修复。
3. **禁止**用 `write` / `edit` / sed / 脚本 `open(...,"w")` **整体重写**工程文件；
   也**禁止**「顺手统一行尾」「顺手加 BOM」「顺手转成 UTF-8」——同一个工程里 `.uvprojx`
   是 LF、`.uvoptx` 是 CRLF 是**正常**的，统一格式化本身就是破坏。
4. **禁止**对这两份文件做有损中间处理：一次 `errors="replace"` 或 `latin-1` 兜底解码
   就足以让中文路径变成 `?`，而且看不出来。需要读字节时用 `project_file_check` 的字段判断。
5. **保持 Keil 的原文风格**：不改缩进、不改属性顺序、不重排节点、不加 XML 声明。
   文本级替换只动目标节点，diff 才干净。新增行的**行尾与缩进都取自工程本身**
   （`add_files` 已按原文件量出来再逐行拼装，不再写死 `8`/`10` 空格）。
6. **工程打不开时先体检、再修复，别猜**：`build` 回 `exit 15` 时先 `project_file_check`
   （看 `bom` / `xml_ok` / `literal_newline_suspects`），再 `project_file_repair`
   （默认 `dry_run`；BOM 与字面量换行都能修）。`exit 15` **不是**「Keil 被占用」，
   不要去关 Keil 实例。
6. **Keil 开着同一工程时不要写**：`uvprojx_edit` 会返回 `project-open-in-keil` 拦住；
   先 `close_uvision`，改完再 `launch_uvision`。
7. **发现损坏先还原，再重做改动**：`project_file_check` 的 `notes` 里
   `U+FFFD`（曾被 `errors='replace'` 写过）、`xml_ok=false`（uVision 打不开）、
   `mixed_newline`（混合行尾）都是可判定信号。修法是从版本库或
   `<工程>.uvprojx.mdkdebug.bak` 还原，**不要在坏文件上继续改**。

**一句话判断「这次改成功没有」**：`project_file_check` 里 `encoding`/`bom`/`newline`
与改前一致、`xml_ok=true`、`sha256` 已变——三者同时成立才算改成功。

**别漏了「字面量换行」这一类**：如果工程里出现 `>LF` / `>CRLF` 紧跟空白再跟 `<`
（例如 `</Group>LF        <Group>`），说明某个写入器把**行尾标签**当成了分隔符写进文件。
这种损坏**XML 仍然合法**（`xml_ok` 是 true），uVision 里表现为内容挤在同一行、分组看着乱，
靠解析校验查不出来。`project_file_check` 会给出 `literal_newline_suspects`，
修法是 `project_file_repair`（**默认 dry_run 只报数**，确认后传 `dry_run=false`）。
**验收不能只看「没有裸 LF」**：必须确认结构行各自独占一行（`<File>` / `<FileName>` 等）。

## 二、六条主线工作流

### 1. 编译 → 烧录 → 进调试 → 看现象（最常用）

```
build_project / rebuild_project        # 先看编译是否过，失败用 parse_build_errors
  → (失败) explain_build_error         # 按错误码/诊断文本给原因与改法
flash_download / build_and_flash       # 烧录（会自动处理调试会话与串口占用）
enter_debug → run_to_line / set_breakpoint → run → wait_breakpoint
read_variable / watch / read_struct / read_registers
```

要点：
- 断点优先用**符号名**（`set_breakpoint(expr="main")`），裸地址会走 Thumb 位归一与
  地址合法性检查，失败时返回 `error 57` 的专属排查提示；
- `run_timeout` 的超时看 `pc_confidence`：PC 读数不收敛时它会给低置信，别当结论用；
- 停机过久怕被看门狗复位：`stop` / `enter_debug` 已自动冻结 IWDG/WWDG，失败会在
  `warning` 里说清。
- 三个烧录类工具的返回值里带 **`symbol_rebind`**（烧录＝符号漂移的源头，服务端顺手对齐）：
  `rebound` ＝ 符号已自动钉到刚烧的 `.axf`；`kept-explicit` ＝ 你此前 `set_symbol_file`
  显式选过，服务端**没覆盖**（要继续调新固件就按 `next_actions` 切，做 App 重定位/双工程
  对比调试就保持）；`already-current` / `skipped` 会如实说明为什么没动。

### 2. 只读排查（不动目标）

```
keil_health → get_status → diagnose         # 通道通不通、现在什么状态、一键聚合体检
snapshot → 改配置 → snapshot_diff           # 内存/寄存器快照对比
query_memory_map / read_peripheral / svd_decode   # 地址属于哪块、外设寄存器什么值
fault_report / wait_fault                   # 异常与硬件错误现场
watch_reset                                 # 反复复位/启动即死：按间隔读 DHCSR.S_RESET_ST（可传 flags_addr 交叉验证）
coverage_start → coverage_read → coverage_stop   # 跑到哪些函数/行：DWT PC 采样，不停目标
trace_etm_probe                             # 先问「这块板能不能抓指令 trace」：只探测不抓取，抓不到直说
trace_eventrec                              # 读 MDK 原生 Event Recorder 缓冲（纯 SWD 可用；要目标插桩，没插桩会说清）
view_render(data_file=...)                  # 把上面任意采集结果渲染成一张能缩放/回放的单文件网页：别手写 HTML
```

**多核目标先问是哪个核**：`core_info`（我连的这个核是哪一款内核）/ `core_list` + `core_select`（OpenOCD 链路真列真切；Keil 链路如实报不支持——一条 UVSOCK 会话就绑当前调试的那个核，双核要分别在两个 target/工程里连）。两个核的 SCS 地址完全一样，**读到的现场属于谁只由调试器当前挂的 AP/target 决定**。

### 3. 串口日志（宿主机侧，不经 Keil）

```
serial_list_ports → serial_monitor_start(port=..., baud=...)   # 常驻采集，落环形缓冲
serial_read(since=<上次的 next_seq>, max_items=200)            # 增量读，不重复刷屏
serial_expect(pattern="msh />", send="help", eol="auto")        # 发命令 + 等回显
serial_write(text="...", eol="crlf")                            # 裸写
serial_monitor_stop                                             # 收工释放 COM 口
```

要点：`eol` 是关键参数（`crlf`/`cr`/`lf`/`auto`），照抄示例免得设备不回话；
进调试/烧录/重启 Keil 会自动释放串口占用，已收日志仍可继续 `serial_read`。

### 4. Modbus（规范 RTU/ASCII + 非规范裸帧）

串口日志监听（`serial_*`）是**按行**切分的，接不了二进制帧协议——调 Modbus 走这一条：

```
modbus_scan(slaves="1-16", port="COM9", baud=9600, serial_format="8E1")  # 先确认从站号/波特率
modbus_read(slave=1, func=3, addr=0, count=10)      # 首次给 port，之后同会话可省略
modbus_write(slave=1, func=6, addr=0x10, value="0x1234", verify=True)
modbus_raw(req="01 03 00 00 00 01", auto_crc=True) # 私有协议裸帧
modbus_sniff(duration_ms=3000)                      # 旁听（不发字节）
modbus_session(action="close")                     # 用完还口
```

要点：
- **失败分类别混着猜**：一个字节都没收到 → `modbus-timeout-no-response`（接线 / 波特率 / 从站号）；
  收到了但 CRC 不过 → `modbus-bad-crc`（串口参数 / 串扰）；从站回了异常帧 → `modbus-exception`
  （**它在线，只是拒绝了参数**，按异常码改地址/数量/取值，别当通信故障查）。
- 拿不准帧结构先用 `modbus_decode` **离线**解一遍（不占端口、不发字节），再去动总线。
  它会**自动判方向**（先按应答解、不符再按请求解）：旁听抓到的帧多半是主站请求，
  结果里的 `direction=response/request` 告诉你是哪边发的；`05`/`06`/`08`/`16` 这类
  请求与应答**同形**的功能码如实标 `ambiguous`，不硬指一个方向。
- Modbus 会话会**独占** COM 口（空闲 900s 自动释放）；要接着看日志或开串口助手，先
  `modbus_session(action="close")`，否则会 `WinError=5`。

### 5. UVSOCK 不可用时的降级通道（命令行批处理）

UVSOCK 被模态框、端口冲突或 Keil 未启动挡住时，用 UV4 的 `-d` 批处理：

```
batch_debug_script(init_file=...)   # 每轮 15~25s；命令报错不改退出码，需读 trace
```

注意三条硬限制（工具会做静态告警）：命令报错不改退出码、`DISPLAY`/`SAVE` 与
`Go main` 会挂死。可重复的冒烟回归适合它，交互式调试仍应走 UVSOCK。

### 6. 只有固件没有工程：`.hex` / `.bin` / `.elf(.axf)` / `.lib` / `.so` → 工程骨架

```
recover_probe(file, detail="compact")         # 先看容器、架构、向量表、能恢复出多少（大固件用 compact）
recover_symbols(file, deep=true)             # 函数清单（observed/inferred/weak 三档置信）
recover_disasm(file, symbol="main")          # 按符号或地址区间反汇编（需要 capstone）
recover_project(file, out_dir="...")         # 出 sct/ld/头文件/startup/stub/反汇编/map/report
recover_project_exact(file, out_dir="...")   # 出**字节精确可重链接**工程（armasm + sct + uvprojx）
recover_verify(project_dir, image=file)      # 真工具链重链接，逐字节比对（byte_identical）
recover_ledger(project_dir, image=file, claim=...)  # 闭环台账：哪条义务被什么证据闭合了 + 主张等级
```

**这条路的三条预算与闸门**（批次90，都是「别让工具替你猜」）：
- `recover_project_exact` / `recover_project` **只对 ARM(32) 成立**（armasm + armlink）。
  判出来是 arm64 / x86 / x86_64 / riscv / mips / ppc / m68k / sparc / mos65xx 时**直接拒**，
  并列出还能做什么（`recover_probe` / `recover_symbols` / `recover_disasm` / `recover_diff` /
  `image_split`）——以前要等到 `recover_verify` 的 armlink 才炸成一句「链接失败」。
  架构**未判定**不拒（判不出来 ≠ 不是 ARM），但这条链的目标对不对没有证据。
- `recover_probe(detail="compact")`：每函数只留 `addr_hex/name/size/confidence/sources/
  n_callers/callee_count`，字符串前 10 条，调用图只留计数；**结论与计数一个不改**，
  被裁掉的条数写进 `omitted`。实测同一份固件 45.1 KB → 8.9 KB（20%）。
  另两个预算参数：`max_functions`（函数总数上限，超了 `truncated=true`）、
  `max_insns`（深度扫描预算，触顶**如实写进 gaps**——以前是静默截断）。
- `image_split(..., out_dir=...)`：把每个镜像按 `offset..offset+length` 切成
  `image_00.bin` 并回读 SHA-256，切出来的字节直接喂 `recover_project_exact` / `recover_probe`
  （目录必须不存在）。不给 `out_dir` 就一个文件都不写。
- `recover_project_exact` 的 `next_actions` 里直接给一行**可复制**的 `recover_ledger(...)`，
  Flash/RAM 窗口已按这份镜像的布局算好；没有 RW 段时会明说「ram 只能你自己给」。

**台账的窗口也可以不传**（批次91）：`recover_ledger(project_dir=…, image=…)` 就够——
Flash 窗口按 manifest 的 `chunks` **实际覆盖范围**推，RAM 窗口按 `manifest.windows.ram`
（出件时由 ELF 的 RW 段算出）推，老产物没有这一项就现读原镜像的 ELF；纯 bin 推不出来
就如实写进 `notes`，不编一个。**推出来的窗口只当上下界**：
- 落点在范围内 → 判据从 `unverified` 抬到 `plausible`（说明「没落空」，不等于按手册核过）；
- 落点在范围外 → 记 `unverified` 并写明「不判 invalid」——「落在我没 dump 到的那一段」
  和「向量表坏了」不是一回事；
- 硬错误（SP=0 / 全 1、复位地址 bit0=0）照样判 `invalid`，不被这条豁免。
要按器件手册把落点核完、并允许判 `invalid`，就显式给 `flash_start/flash_size`、
`ram_start/ram_size`——输出里 `windows{flash,ram,basis,derived,note}` 会说明用的是哪一套。
裸 bin 也不再要求另传 `base`：没给就取 manifest 的首块地址。

**先自证再用**：`recover_project_exact` 自己不说成功，判据是 `recover_verify` 的
`byte_identical=true`。两条路分工：`recover_project` 出「能读能改的骨架」，
`recover_project_exact` 出「原样复刻、能证明」。要点：
- 复刻的是 `PT_LOAD` 的 `filesz`（段才是进 flash 的字节），不是节表；
- 期望字节优先由 `fromelf --bin` 抽原镜像（独立证据），没传 `image` 时工具会明说
  「本次没有独立证据」；
- `diff.alignment_padding` 是 armasm 的 4 字节对齐填充（原镜像长度不是 4 的倍数时），
  不算差异；其余任何长度/字节不同都判 `false`；
- `armlink` 的 `L6305W`（没有入口点）是**预期**：Cortex-M 入口在向量表里；
- 产物的 `.uvprojx` 是模板改造来的，**器件是占位**，烧录前必须改成你的芯片；
- `.lib` / `.o` 仍被拒（重定位目标没有最终地址）。

**函数形状与参数推断**（批次81 吸收 Ghidra 的口径，零额外依赖）：`recover_symbols` /
`recover_project` 的每个函数现在带 `body_basis`（`return` / `tail_call` /
`indirect_branch` / `next_entry`）、`params_estimate`、`returns_estimate`，
thunk 另带 `is_thunk` + `thunk_to`。读这些字段的口径：
- `body_basis` 说明函数体是**怎么结束的**；`next_entry` 表示没找到终止指令、
  只能切到下一个入口，这一段的可信度最低（可能把数据算进来）；
- `params_estimate` 是按 AAPCS 看 `r0..r3` 首次访问是读还是写估的，**只是估计**：
  头文件里仍声明 `void f(void)`，别拿它当真实签名去改调用方；
- 想要「能读的代码」用 `recover_disasm(..., fmt="c")`（见下），别再靠猜 `op_str`。

**寄存器级伪 C**（批次84，零额外依赖）：`recover_disasm(file, symbol="X", fmt="c")`
把单个函数提升成寄存器级 C；`recover_project` 默认额外写 `src/pseudo_c.c`
（`include_pseudo_c=false` 可关，`max_pseudo_c_functions` 默认 60）。读法：
- 它保的是**表达式与跳转的语义**，不是原始源码。批次92 起变量不再一律叫 `rN`：
  依次尝试 `a0..a3`（入口四个参数位）→ `i` / `j`（回边里自增自己被 `cmp` 的计数器）→
  `p0` / `p1`（基址，≥2 个不同非零偏移）→ `v<N>`。**这四个名字都是推断**，
  判断依据写在返回的 `renamed[].basis` 里，别把 `p0` 当成「真的有个指针变量」。
- 类型默认 `uint32_t`；只有当**消费这个值的指令**给出了单向证据才改成 `int32_t`
  （`ldrsb/ldrsh/ldrsw`、`asr`、有符号比较分支…；`ldrb/ldrh`、`lsr`、无符号分支…
  反推 unsigned）。两向证据都在 ⇒ `types.by_reg[..].signed = null` + `note`
  写明冲突，**不猜**。看汇总用 `n_signed_vars` / `n_unknown_signed`。
- 结构体**只给字段表不给结论**：`structs[]` 是「同一基址寄存器上 ≥2 个不同非零偏移」
  的候选，字段宽度按访问指令的存取宽度推，成员名一律 `f_0x<off>`。还原原始
  `struct` 与成员名做不到——类型信息在编译时就没了。
- 内联**只能标边界不能反演**：`inline[]` 给的是「这段指令与另一个函数逐条指纹相同，
  且窗口里有 `bl`」，两种情况（真内联 / 共享尾段）工具都承认，所以措辞是
  「内联或共享尾段；两种情况都没有调用点可还原」。反内联做不到。
- 跨函数只做**一层** `return` 直传：`flow.calls[]` 记每个调用点的实参来源
  （`entry` / `ret:<函数>` / `reg:<N>` / `const`），`ipa.edges[]` 记「A 的返回值
  经 C 传给 B」。不做全局变量传播、不做递归/多层归纳。
- `cpsid/cpsie/bkpt/vmsr/msr/svc/dsb/isb` 只留注释并计数（`control[]`），
  不参与数据流——它们不改任何寄存器值。
- `rename=False`（`recover_disasm` / `recover_project` 的 `pseudo_c_rename`）逐字节
  回到批次91 口径，出问题时的兜底开关。
- `/* 未支持: <mnemonic> ... */` 是**故意降级**不是漏做（典型：进位链断了还碰
  `adc/sbc/rrx`）。看到它就说明这几行的语义不保真，别当等价代码用。
- `flag_<cond>` 表示条件依赖的 flags 找不到生产者（上游是逻辑指令或跨块），
  此时 `if` 里的条件只是「按条件码读出来的那个标志」，不是从比较推出来的。
- `switch` 的项数来自守卫 `cmp`：`bhs/bcs` ⇒ K 项，`bhi` ⇒ K+1 项，其它条件 ⇒
  扫到越界（`confidence=weak`）。跳转表的数据不会伪装成指令出现在源码里。
- 结构化只做**单块 if / 单块 if-else**，循环与其余多块控制流保留 `goto L_xxx`
  与 `/* 回边（循环） */`。别拿「有没有 while」判生成质量。

**多容器与多架构**（批次85）：`recover_probe` / `recover_disasm` 额外收
`arch / endian / bits / thumb / entry`。口径：
- 能识别的容器：ELF、Intel HEX、Motorola **S-record**（`fromelf --m32` 的产物，入口取自
  `S7/S8/S9`）、裸 bin、ar、**PE32/PE32+**、**COFF `.obj`**、**Mach-O**（含 fat，取第一个
  切片并明说）。识别按字节判、每条带判据（`container_evidence`），别看扩展名。
- **裸 bin / S-record / .obj 里没有架构信息，工具不猜**：这时必须显式给
  `arch="arm"`（+`thumb=true`、`endian`、`bits`）和 `entry=`。给了之后报告里
  `arch_declared` 会保留文件自己给的说法，两者并列——冲突看得见，不会被悄悄覆盖。
- 有后端的家族：`arm arm64 riscv x86 x86_64 mips ppc m68k sparc mos65xx`；
  `sh` / `s390` 会明确报「无后端」并列出可用家族，不返回空结果。
- **伪 C 的指令集覆盖**（批次93）：`arm`（Cortex-M 的 Thumb 与 ARMv5/ARM9 的 ARM 模式）、
  `riscv`（RV32/RV64，含 RVC 压缩指令）、`mips`（MIPS32，含分支延迟槽）三个家族。
  做法是**翻译层**：RISC-V/MIPS 指令先按等价语义翻成统一 IR，再进同一个提升器，
  所以类型恢复/变量命名/结构体候选/内联边界/跨函数数据流对这些家族同样生效。读法差异：
  - 寄存器用 ABI 名而不是 `rN`：`riscv` 是 `a0..a7 / ra / sp / t0..`，`mips` 是
    `a0..a3 / v0 / v1 / ra / sp`；调用约定分别是 RISC-V psABI 与 o32，
    返回值在 `a0` / `v0`。
  - **写零寄存器是丢弃**：`addi zero,zero,1` 出来的是 `/* 结果丢弃 ... */` 注释，
    不会给你一个叫 `zero` 的变量（`x0/$zero` 恒为 0，追它的赋值是白费）。
  - MIPS 的**分支延迟槽已提到分支之前**（notes 里有「N 处分支延迟槽已提到分支之前」，
    N 是实际搬动的次数）：伪 C 里的顺序是**执行顺序**，不是地址顺序。
  - RISC-V 的分支立即数是**相对偏移**、MIPS 的 `j/b/jal` 是**绝对地址**；翻译层已
    统一折算成绝对地址，注释里给的是折算后的目标。
  - 翻不动的形态（原子 `amo*`、MIPS `rotr/mtlo` 之类）统一出
    `/* 未支持: <mn> ... */` 并计入 `n_unsupported`——**不是漏做，是没建模**。
  - 明确不做的家族会拒绝并给理由：`arm64`（本提升器的类型层是 32 位）、
    `x86/x86_64`（子寄存器 + 隐式栈）、`ppc`（CR 字段与 update 后缀）、
    `m68k`（两套寄存器组 + 前后自增寻址）、`sparc`（寄存器窗口）、`mos65xx`
    （8 位累加器机）。这些用 `recover_disasm` 看汇编。
- **armasm/armlink 复刻链仍只对 ARM**：伪 C 放开家族 ≠ 能按 RISC-V/MIPS 出可编译
  工程（那条链的伪指令、ELF 与启动细节都是 ARM 的）。
- **可重定位目标（`.obj` / `ET_REL` / 库成员）不要拿去出工程**：地址是节内偏移，
  `recover_project*` 一律拒并给替代动作（先链接，或先 `recover_probe` 看节与符号）。
- PE 里的地址一律 `ImageBase + RVA`，`recover_disasm(addr=...)` 收的是**最终地址**。
- **读字节必须有出处，而且要能重读校验**（批次94）：`recover_disasm` 的输出多两项——
  `source{file_offset_hex, span, requested, got, clipped, reason}` 说明这批字节从文件
  哪个偏移读的、落在哪个映射段、有没有读不全；`address_map{container, base_hex,
  base_applied, note, spans}` 说明 `base` 到底有没有生效。三条读法：
  - `source.clipped=true`：请求越过了段尾/文件尾，**只拿到 `got` 字节**，原因在
    `reason`。这时结果只覆盖到那儿，别当成「函数就这么长」。
  - `address_map.base_applied=false` 是正常的：ELF/HEX 自带地址，`base` 对它们
    **不叠加**（以前是静默忽略，调用方以为自己平移过了）；裸 bin 才是 `true`。
  - 工具会**逐条回填校验**（解码用的字节 vs 按同一地址重读），不一致直接 `ok=false`
    + `mismatches[]`。看到它别重试同一组参数，先看 `address_map.spans` 与 `base`。
  - **`base` 不自动识别**（批次95）：`base` 只来自你传的参数或容器自带地址。输出里
    `input.base_received_hex` 是**你传的**，`address_map.base_hex` 是**实际用来寻址的**，
    `base_source` 说明哪个生效（`arg` / `container` / `container+arg`）。两者不同不是 bug，
    而是文件自带地址：看 `base_conflict{argument_hex,container_hex,delta}`。
  - 裸 BIN 会做 Cortex-M 向量表自检：`address_map.base_check.verdict` 为
    `not_a_vector_table` 时多半 base 差一页/差整段，`hint` 也会进 `notes`；工具**不会**
    替你改 base。
  - 「我传了 X 它却用了 Y」这类问题，第一件事是把 `input.base_received_hex` 与
    `address_map.base_hex` 贴出来；不要凭 `file_offset` 反推 base（HEX/ELF 上必错）。
  - **裸 BIN 可以不传 `base`**（批次96）：前 8 字节像 Cortex-M 向量表且复位地址不在镜像内时，
    工具按 1KB 对齐推断，并标 `address_map.base_source="inferred"` + `base_inferred{method,
    sp_hex, reset_hex, evidence}`、`notes` 里写「base 是推断的」。显式传 `base` 永远优先；
    数据不像向量表时**不猜、照旧报错**。
  - 报错里的地址统一 8 位补零（`0x08005204`），`file_offset_hex` 仍是文件偏移原样。

**工程优化等级**（批次96）：`read_project_config` 的 `optimization_level` 由
`<Cads><Optim>` 决定，**1-based**（1..4 → `-O0`..`-O3`）；`-Otime` 看 `optimize_for_time`
（来自 `<Cads><oTime>`，与 `<OptFeed>` 无关）。越界返回 `optimization_error`，不猜。
要 100% 确认时打开工程 `CreateBatchFile`，直接读构建生成的 `.bat` / `.__i` 里的命令行。

**两版固件比对 / 库函数指纹识别**（批次86）：`recover_diff(reference, target, ...)`。
读法只有一条：**「名字对上了」和「代码对上了」是两件事**。
- `basis="name"` 只是对应关系（两侧符号表同名且唯一），真正回答「代码没变」的是
  `bytes_equal`：`true` / `false`（改过）/ `null`（区间或架构证据不足，判不了）。
- `basis="bytes"` 才是字节相同，且要过四道：区间**有证据**（`size_trust` 为 `symtab`
  或 `control_flow`，`guessed` 一律不进）、长度相等、指纹两侧唯一、架构相同。
- `state="candidate"` / `basis="insn_fingerprint"` 是**线索不是结论**：指令序列规范化后
  相同（代码内地址归一成 `<CODE>`），可能是整块搬移，也可能是不同源码编出同样指令。
- `only_left` / `only_right` 只说「本次清单里没有精确对应」——重命名、内联、strip、
  字节变动、发现不全都能解释，**不证明源码有增删**；`inventory_complete` 恒 `false`。
- 重名/重指纹进 `unresolved`，工具**不展开**这些组的配对（`bx lr` 桩会炸出噪声）。
- 建库：`save_reference_sig="x.sig.json"`（默认不覆盖，写了回读校验）；之后两侧都可以
  用 `reference_sig` / `target_sig` 直接吃库，省掉重复分析。ar 归档不给建库（地址是节内偏移）。
- 两侧共用一套 `arch/endian/bits/thumb/entry`；裸 bin 必须显式给 `arch`，
  `*_base` 用于把裸固件的装载地址对齐到 axf 的地址空间。

**一颗 Flash dump 里切出几个镜像**（批次87）：`image_split(path, base=..., flash_start=...,
flash_size=..., ram_start=..., ram_size=...)`。读法：
- 证据只有三类：**向量表**（初值 SP 非 0/全 1 且 4 字节对齐、复位地址 bit0=1、随后 6 个
  handler 字里 ≥75% 像代码地址）、**擦除带**（连续 0xFF ≥ `erase_min`，默认 256）、
  **容器自报长度**（gzip/zlib/bz2/xz/lzma 解到流尾，精确；lz4/zstd 报 `not_supported`）。
- 给了 `flash_start/flash_size` + `ram_start/ram_size` 才是 `strong`，否则是 `plausible`
  （只判过「非 0 + 对齐 + 地址在文件范围内」）。
- 每个镜像的 `length` 都是推导值，看 `size_basis`：`erase_gap`（到擦除带，最可靠）/
  `next_vector_table`（到下一个表，上界）/ `end_of_file`。
- `coverage.unassigned_bytes` 是「不属于任何镜像、也不是擦除态」的字节：那里还有东西，
  但没有证据说是镜像，别当成空洞。
- 只找 Cortex-M 向量表；RISC-V/ARM9 起点要靠 `recover_probe` 的容器证据。HEX 空隙被填
  0x00，**不据此**判擦除带。

**恢复好之后**：`recover_ledger(project_dir, image=file, flash_start=..., flash_size=...,
ram_start=..., ram_size=...)` 出**闭环台账**（批次88，吸收 REA obligation-ledger 的 fail-closed 口径）。
读法只有三句话：

- 8 条具名义务，每条要求特定证据强度：`unsupported < unknown < derived < observed`。
  **derived 不能闭合要求 observed 的义务**；`unknown`（判不了）与 `unsupported`（做不到）
  **永不算通过**，也不算失败；缺证据是 `open` 并附 `required_next_evidence`，
  `failed` 必须有 observed 级反证。
- `ready=true` 的含义严格限定为**字节/布局/工具链链路**被观察证据闭合：**不表示它能跑**
  （`runtime.bootable` 恒 unknown），也不表示它是好固件；C 语义恒 `unsupported`。
  没闭合就去看 `summary.blocking_obligations` 与那几条的 `reason`。
- 三种取证：默认跑 `recover_verify`（真工具链）；`verify_json=` 复评一份已保存的 verify 输出
  （不重跑，`closure_digest` 与实跑相同，可用于对账）；`skip_build=true` 只盘点材料。
  不给 RAM/Flash 窗口时向量表判据只到 `unverified`（SP 落点与复位落点未核），台账会写在 reason 里。
- 主张等级 `claim=`（批次89）是**正交的第二问**：`shipped-artifact` / `controlled-replay`（默认）/
  `live-observation` / `external`，每级只对**它覆盖的义务子集**负责，并限定**允许的来源类别**
  （`shipped-artifact` 读交付字节 / `controlled-replay` 我们自己重链接 / `live-observation`
  调试器或板上实测 / `external-service` 外部工具结论）。**强度够不等于来源对**：来源不合规的那条
  会被写成 `claim_status=unknown` 并进 `claim_blockers`，但它自己的 `status` 不变，
  `closure_digest` 也不变（换 claim 得同一个 digest，可跨调用对账）。
  `verify_json=` 是回放，`claim_note` 会写明它**不能顶替本次实跑**，也不支撑 `live-observation`/`external`。

**关系层与类型层**（批次82/83）：`recover_symbols` / `recover_project` 的
`report.json` 里另有 `relations`：`xref_counts`（call/branch/data_read/data_write）、
`call_graph`（根/叶/环/深度）、`switch_counts`、`types`（栈槽/结构体候选/数组元素
大小/全局对象）。全是**形状**，不带类型名：4 字节就是 4 字节，别读成 `int`；
`n_unresolved` 是「基址寄存器静态定不下来」的条数，不做符号执行就不猜。

要点：
- **三档置信要当真**：`observed` 来自 `symtab`/DWARF；`inferred` 来自向量表或 `bl` 目标；
  `weak` 只有一条「代码指针」线索。**别把 `weak` 当函数名用**，也别把 inferred 的
  架构当成读到的（HEX/BIN 没有 ELF 头，架构是从复位向量 bit0 推的，报告里有 `basis`）。
- **`.lib` / `.so` 不要直接出工程**：`ar` 成员是可重定位目标文件，地址是节内偏移；
  `recover_project` 对归档只做逐成员取件 + `manifest.json`，要反汇编请对单个成员调
  `recover_disasm`。
- **`out_dir` 必须不存在**（独占写，绝不覆盖既有证据），默认生成物每个都回读 SHA-256。
- **给的是寄存器级伪 C，不是原始源码**：参数个数/类型、结构体布局、局部变量名、宏、中断优先级都不在输入里，
  `report.json` 与生成的 `README.md` 专设「没有恢复什么」一节——那份清单是**边界声明**，
  不是待办。

## 三、接续上一次的上下文

MCP 工具无状态，会话一断，工程/符号/断点清单就没了。开工与收工各一次：

```
session_state(action="show")                        # 当前上下文 vs 磁盘态差异
session_state(action="save")                        # 收工落盘（原子写，旧文件备份 .bak）
session_state(action="load", apply=true)            # 开工接续：只恢复主机侧可逆项（符号文件）
```

`load` 默认**只读不应用**；断点/内存/运行态等目标侧状态永不自动重放——
需要时按 `context` 里的 `expr` 自己重新下命令。

## 四、省上下文的三个旋钮（高输出工具通用）

`list_tools`、`snapshot`、`read_mem_multi`、`batch`、`parse_map` 等一批高输出工具的返回体
可能很大，它们都接受：

- `max_lines=N` —— 列表最多返回 N 条；
- `compact=true` —— 去空值字段、公共字段提升、说明性长文本截断到 200 字符；
- `full=true` —— 强制全量（覆盖上面两项与环境变量默认）。

**裁剪绝不静默**：只要丢过东西，返回体里必有 `output.truncated/dropped/trimmed/hint`，
还会提醒你 `count/total` 等计数字段仍是全量数字。要下结论时用 `full=true` 再看一遍。
也可以用环境变量 `MDKDEBUG_COMPACT=1`、`MDKDEBUG_MAX_LINES=200` 设全局默认。

## 五、参数与工具面的约定

### trace / 观测类工具的 `link` 参数

RTT、变量 scope、halt 采样、DWT 计数、PC 采样这些**观测**工具在 Keil 与 OpenOCD 两条链路上通用，都接受 `link=auto|keil|ocd`（默认 `auto`）：

- `auto`：哪条链路有活会话用哪条（两条都有时优先 Keil）；
- Keil 侧先 `enter_debug`，非 MDK 侧先 `ocd_start`；
- **显式指定而那条不可用时不换另一条顶上**，直接报错并给出两条链路各自的原因与起法；
- 读回来的数据带 `read_confidence`/`while_running`/`degenerate`：**读到的 0 不等于数据是 0**，可疑时先看这些字段再下结论。

只有 SWO（`trace_swo_*`）本身依赖 OpenOCD（TPIU 配置与落盘在那里）；Keil 用户做printf trace 用 `itm_trace`（读 Keil 的 Trace 缓冲，已带 ITM 结构化解码）。

### 运行态读写内存：`running=live|halt`

`read_mem` / `write_mem` 的 `running` 默认 `live`——**不要求目标已停**（Keil 链路真机实测：全速跑时读 SRAM / 外设 / 256 B 大块均成功，连读 `SysTick->VAL` 能拿到真实的递减值）。

- `live`：直接读 / 写，结果附 `while_running`。运行态读数会自动复读比对，两次不一致时给 `read_confidence=medium` + `read_unstable`，并**同时列出两种解释**（地址本来就在被 CPU 改写 / 读的中途被运行中的目标打断），不替调用者下结论。
- `halt`：**停-读-走**（或停-写-校验-走）快照——自动 `stop` → 操作 → `run`，返回 `sampling` / `was_running` / `paused_ms` / `resumed` / `halt_note`；**会打断目标、改变现场，属有副作用操作**，只在确实需要「某一瞬间的一致快照」时显式使用。

- **参数别名**：`query`/`name`/`expression`、`addr`/`address`、`timeout_ms`/`timeout_s`
  这类直觉写法都能落地；但**未列出的参数名会被拒绝**（不会静默用默认值），报错里会列出可用参数。
- **工具面默认精简**：默认只暴露 44 个（`core` 38 个 + 6 个元工具），其余 171 个按需装载——
  `toolset(action="load", toolsets="mem,trace")` 装回来、`toolset(action="status")` 看现状；
  启动时也可用 `MDKDEBUG_TOOLSETS=serial` 指定（参数优先），`=all` 全开。可用组名见 `capabilities`；
  `tools_groups()` 列组/档总览、`tools_load(group="mem")` 等价装卸（新入口，参数更少）。
  **符号修复手段 `set_symbol_file` / `list_symbol_projects` 已在默认面（`core` 组，批次67 起）**——
  `env_check` 报「符号与固件不同源」时，`next_actions` 第一条就让你直接调 `set_symbol_file` 切到刚烧录的那份；
  只有当你把 `core` 组从面上裁掉（如 `MDKDEBUG_TOOLSETS=mem`）时，它才会把「先 `toolset(action="load", toolsets="symbol")`」这一步补在最前面；
  自己手工切符号时也记得先装这一组，否则只会撞「未知工具」。
- **上下文不够时的三把刀**：`nano` 极简档（`MDKDEBUG_TOOLSETS=nano`，19 个工具 / 约 1.5 万字节
  线上载荷，自动用 `min` 描述档；含 `mdk_guide`，正文取回不用另外装）＋ **描述分层** `MDKDEBUG_DESC=full|lean|min`（批次74 起**默认 `lean`**，`nano` 档自动 `min`；`MDKDEBUG_DESC=full` 整面逐字节还原）
  ＋ **结构瘦身**（默认开，`MDKDEBUG_SURFACE=off` 关闭）：只改 tools/list 线上副本，
  去掉恒定样板的 `outputSchema`、inputSchema 里的注释性 `title`、annotations 里等于规范默认值的字段；
  活的注册对象与调用路径一个字不动。
  描述分层只把「参考手册」式长正文挪出上下文，正文一字不改地归档，
  用 `mdk_guide(topic="tool", name="read_mem")` 可逐字取回；**结构化尾块
  （【输出控制】/【参数】/【风险】）与正文结尾的关键告警一定保留**——
  宁可多留字符，也不让描述出现「参数在、说明没了」。
- **统一信封**：所有工具返回体都带 `status`（ok/error/…) 与 `next_actions`（下一步建议）；
  失败时还有 `error_code` 与 `error_hint`。

### 插桩 trace 的两种工作模式：stream 与 buff

内核/固件往往跑得比调试器读得快——**不插桩、靠轮询读 SRAM 看高频事件是走不通的**
（全速跑时读回全 0，halt 读又把现象冻住）。正确做法是让目标自己攒证据：

| | `backend="buff"`（全速录、事后搬） | `backend="rtt"` 等（持续录持续读） |
|---|---|---|
| 谁在搬 | 目标写静态环形缓冲，调试器只在 dump 时读一次 | 调试器按节奏持续读 |
| 目标是否停 | **运行期间完全不停、不 halt** | 读的时候会 halt，目标被反复冻一下 |
| 时间粒度 | 目标侧 DWT，可到 **10ns 级**（`buff_ts_shift=0`） | 受读取节奏限制 |
| 适合 | 全速跑一段、事后离线分析（任务切换、异常现场） | 人在旁边盯着看的实时调试 |

工作流：

```
trace_instrument(backend="buff", buff_records=2048, buff_ts_shift=0,
                 buff_clear_on_init=false, fault_frame=true)   # 生成组件+配置，编烧
  → 跑目标（跑多久都行，目标不停）
  → trace_buff_status(elf=..., addr=...)     # 先看控制块：total/lost/wrapped/是否有新记录
  → trace_buff_dump(elf=..., addr=..., out_file="trace.json", names="0x10=switch")
  → trace_buff_reset(elf=..., addr=...)      # 下一轮前清空
```

硬规矩（都是真板上撞出来的，详见 [PITFALLS 第十七节](../docs/PITFALLS.md)）：

- **读回全 0 不等于缓冲是空的**——目标全速跑时经调试器读 SRAM 一律返回 0，
  工具会报 `buff-read-degenerate` 并要求先 `stop`。**`0` 的语义是「没读到」，不是「没有」。**
- `stop` 后**第一次** `read_mem` 是脏帧，必须重读复核。
- 用 `lost` / `wrapped` 判完整性：回卷时看到的是**一个窗口，不是全程**；
  分块 dump 之间必有空洞，要连续记录只能**把缓冲开大**、一次读完。
- 时间戳必须用 DWT_CYCCNT（组件已幂等使能 `DEMCR.TRCENA`）；拿内核节拍当时间戳会让
  10µs 级切片全退化成 `dt=0`。
- `trace_buff_reset` 是**延迟生效**的（目标在下一次写记录时才处理），
  返回体用 `applied` / `request_latched` 区分「已清空」与「只落了请求」，别把后者当成功。
- **「没插桩」不等于「没发生」**：`WAIT` 只覆盖 `wait/wait_period/block` 三条路径，
  其余阻塞在这条时间线上不可见。桩点清单本身就是这份 trace 的可信边界。

**第三种：SWD 无缝 stream（只接 SWD 两线，批次56）**——目标侧用「四元组字典 + varint」
把事件压到 1~3 字节写进环形缓冲，调试器按节奏**停机搬走**（既不是 buff 的「全速录到事后一次读」，
也不是 rtt 的「持续读」）。三条硬规矩（真机撞出来的，详见 [PITFALLS 第十八节](../docs/PITFALLS.md)）：

- **搬运间隔必须短于「环容量 / 事件率」**：8 KB 环 @ 约 10k 事件/s 只有 0.22 s 窗口——
  0.25 s 节奏丢 29,015 条，**0.12 s 节奏 `lost_events = 0`**。缓冲开大只是把窗口拉长，
  节奏不对照样丢，两个数要一起算。
- **读环必须停机**：目标全速跑时读 SRAM 可能整片读回 0（如实报 `swd-read-degenerate`）——
  **丢的是「没读到」，不是「没有」**。停机搬走不会丢数据（背压保证任何时刻已录的那段都完整，
  丢的只是事件，不是结构）。
- **时间粒度可调，但它决定的不只是分辨力，还有「录不录得下来」**：
  `trace_swd_reset(granularity=...)` 是唯一入口（`cycle` / `500us` / `none` / `1ms` /
  `1us` / 直接给微秒数，见 `trace_guide(topic="time_granularity")`）。实测每事件字节数：
  `500us` ≈ **1.01 B**、`10us` ≈ **1.31 B**、`1us` ≈ **2.33 B**、`cycle` ≈ **3.33 B**。
  环只有 8 KB、停机搬运一轮 ~1 s，可持续搬运有限（实测约 6~9 KB/s）：
  **粒度调得比事件间隔粗，dt 会整批算成 0，时间轴冻在原点**（宿主报 `time_axis_frozen`，
  渲染 badge 报「冻结」）——那不是「事件同时发生」，是量化把余数丢了；
  **调得太细，每事件字节数上去，一旦超过搬运能力就会一路丢**（丢一条 ⇒ 清字典 ⇒
  下一条必是 LIT ⇒ 更快填满，正反馈）。F427 上的实测甜点是 `10us`。
  要真时间轴又不想丢，正解是**把 `limit` 压到刚好盖住本批**（给太大反而每轮序列化
  整个会话、越调越慢）并把节拍调紧，而不是继续抠别的。
  `trace_swd_read(granularity=...)` 只做校验，不符会报
  `swd-granularity-mismatch` / `-changed` / `-invalid`。失步报 `swd-stream-desync`，
  正解是 `trace_swd_reset` 重对齐（别硬解，字典不同步会解出看着合理的错误 key）。
- **`events` 默认是「会话尾部」，不是「本批新增」**：自己写循环录一段、要离线回放时，
  `events.extend(out["events"])` 会把前几次调用的事件重复收集（拼出来是 N 个重叠窗口，
  条数好看但是重复计数）。**拼线性轨迹要传 `only_new=true`**，那样 `events` 只给本批的
  `new_events` 条。`counts_by_type` / `top_ids` / `faults` 始终按**整个会话**统计。
- **任务名是主机侧「用 DWARF 反查」出来的，固件一个字节都不用改**：`trace_swd_read(tasks=auto)`
  会按 `svcrt_task_table` 的元素类型（`svcrt_task_t`，**匿名 typedef 结构体**）取出 `entry`
  字段偏移，逐槽读 TCB 入口指针、反查 ELF 函数符号，给 `sched`/`wait`/`ready`/`create`/
  `exit` 事件补上 `from_name`/`to_name`/`task_name`/`name`（数字 id 原样保留，`task_names`
  给出整张表）。**名字后到会回头补**：解析成功那一刻之前的历史事件也会被重命名一遍。
  **只认精确符号**（入口地址 = 函数首地址）：跨镜像的入口（SVCrtOS 的 app/驱动是
  另外下发的镜像，任务入口不在这份内核 `.axf` 里）**合法但无名**——这种槽位留空不编，
  给 `unmapped_slots` + `hint` 说明怎么取名；名字查不到就**不写名字**（不是写 `?`），
  只有**所有**非空槽都落不到符号表里才整批拒绝（`tasks-snapshot-inconsistent`）。
  `trace_swd_tasks` 单独看这张表为什么没名字（`read_mode`/`errors`/逐槽 `entry`）。
- **要连 app/驱动的名字一起拿，就把多份 `.axf` 一起传**：`elf="内核.axf;app.axf"`
  （`;` 或 `,` 分隔）。布局/任务表取**第一个具备者**，名字从所有镜像按精确首地址匹配，
  命中不在第一份时记 `sym_from`；**跨镜像的名字必须过内容核对**（板上该地址的机器码 ==
  那份 `.axf` 同地址的字节）才写上去——地址命中只说明「那地址在那份构建里是函数首地址」，
  不说明**板上跑的就是那份构建**，核不过/核不了就丢名、计入 `unconfirmed_slots`。
  任一路径不存在报 `tasks-elf-missing` 并点名。返回 `elf` 是第一份、`elfs` 是全部；
  真实情况里「一个名字都补不上」很常见（镜像根本不在手上），那时照旧 `ctxN` + 说明。
- **渲染不用自己喂任务名**：`view_render(data_file=…)` 会自己从返回体的 `task_names`
  里取名字，任务泳道直接是人可读的名字；idle 按 `idle_id` 单独命名，中断轨道走
  另一套命名（异常号），不会被任务名污染。

**桩该插在哪儿**（`trace_guide(topic="instrument_points")` 有完整版）：异常 handler 第一条指令
（`MDK_TRACE_FAULT_CAPTURE()`，一次拿到 PC/LR/SP/xPSR + CFSR，性价比最高）→ 喂狗点与复位原因
→ 任务/上下文切换点 → 状态迁移点。高频中断最内层、被内联的小函数、时间敏感临界区不要插。

### 等一件事发生：`trace_watch`（别一点一点翻事件）

想确认「某个事件发生没发生」时，**不要反复 `trace_swd_read` 逐条扫**——把条件告诉工具，让它等：

```
trace_watch(action="wait", spec="sync,obj=cond,op=wait", timeout_ms=10000)
```

命中就把**命中事件 + 前后上下文 + 诊断结论**一次交回（`hit.event` / `hit.before` / `hit.after` /
`hit.clause` / `diagnosis`）；没命中则给 `coverage`。**「通知 AI」= 一次有界长轮询**
（MCP 服务端不能主动唤醒模型），`timeout_ms` ≤ 60000。

- **条件语言一套管两种事件**：手动插桩事件（自定 `id`，如 `id=42`）与内核自动钩子事件
  （`sched`/`sync`/`heap`/`isr`/`fault`）在同一条流上，`spec` 同时认 `id` 与语义字段。
- **写法**：`|` 是或、`,` 是且、裸词是 `type` 简写。例：`fault`、`sync,obj=cond,op=wait`、
  `isr,id=10`、`t_us>=1500`、`sched,to=3|sched,from=3`、`heap,op=alloc,size>=256`。
  字段/枚举写错**一律报错**（附可用取值）——不静默变成「永不命中」。
- **先预检再等**：`trace_watch(action="test", spec=…)` 在**已录事件**上试判，不改状态；
  `arm` 只装条件（`cursor=len(events)`，历史不计；`cursor="history"` 从会话起点算）；
  `status` 看进展；`clear` 卸掉。
- **没命中 ≠ 没发生**：`coverage.complete=false`（目标丢过事件 / 会话被裁剪 / 一段新事件都没有）
  时就只能说「已录下的部分里没有」。要下「没发生」的结论，先 `trace_swd_reset` 重开一段再等。

## 六、给人看图：`view_render` / `view_guide`

上面采集回来的都是 JSON。要给人看（汇报、贴图、解释「为什么死在这」），**不要从头手写网页**——
把采集结果直接丢给 `view_render`，它出一张单文件 HTML（无外部依赖，`file://` 可开、可直接转发）：

```
trace_buff_dump(elf=..., out_file="trace.json", names="0x10=switch")
view_render(data_file="trace.json", title="任务切换")   # → path，打开即可

view_render(data={...})                  # 也可以内联 JSON，不必落盘
view_render(data={...}, view="scope")    # 已经知道该出哪种图时显式指定
view_guide(topic="howto")                # 不知道该配哪张图？先问它（howto/views/spec/limits/all）
```

四种视图（`view=auto` 按数据形状自认）：

| 视图 | 适合的数据 | 图上有什么 |
|------|------------|------------|
| `timeline` | 任务切换/中断/异常事件流（`trace_buff_dump`、`trace_swd_read`、`trace_record`） | 泳道 + 切换时刻标记（放大后标出切给谁）+ 中断进出区间 + 异常虚线 + **缺口斜纹带** |
| `scope` | 变量/波形样本（`trace_scope_read`）、自写 spec 的算法波形 | 每通道一带；模拟量折线、布尔/枚举阶梯；左侧给 min/max/变化次数/游标当前值 |
| `bars` | 函数/命中的占比排名（`trace_pcsample`、`trace_profile`、`coverage_read`） | 横向条形榜 + 绝对值 + 占比 |
| `report` | `{sections:[...]}` 自组结论页 | 结论块（ok/warn/bad）+ 段落 + 列表 + **可嵌套上面任一种图** |

页面自带：滚轮**以鼠标为锚**缩放、拖动平移、单击定位游标（读数跟着游标走）、双击全览、
`▶ 回放`（按原始时间 1:1 走一遍）、按轨道开关显隐。**每个图都带「边界」栏**：时间轴口径、
抽稀/合并/上限、丢失计数都摊在页面上——**图上看不到的，只能说没被记录/没插桩，不等于没发生**。

三条规矩：

- **认不出来就报错（`view-unknown-data`），不画空图**——空图会被读成「这段时间什么都没发生」。
- **自己写 spec 也要能直接出图**：`{"kind":"timeline"|"scope"|"bars"|"report", ...}`，
  字段说明看 `view_guide(topic="spec")`；结构不对报 `view-bad-spec`，不静默画个半截图。
- **省 token 的用法**：AI 只说「把这个结果渲染出来」，不写一行 HTML/CSS/JS。

## 七、出问题先看这几个工具

| 现象 | 先调 |
|------|------|
| 连不上 / 时通时不通 | `keil_health`、`get_status`、`list_uvision_instances` |
| 表达式集体解析失败 | `get_status` 看 `symbol_stale`，必要时 `set_symbol_file`（在 `symbol` 组、默认不暴露：先 `toolset(action="load", toolsets="symbol")`） |
| 断点/PC 解析出「板上不存在的函数」（假符号） | `get_current_location` 看 `symbol_verified`，再 `env_check` 看 `firmware_symbol` → 按它的 `next_actions` 装 `symbol` 组并 `set_symbol_file` 切到与刚烧录固件同源的那份 |
| 函数名/行号**解析出来了**，但不确定是不是假符号 | `get_current_location` 的 `symbol_verified`：false ＝ 本会话**没核对过**这份符号与板上固件是否同源（解析成功 ≠ 名字可信），跑一次 `env_check` 才会变成 true |
| 断点下不上（error 57/65/145） | 返回体里的 `checks` 与 `hints`，或 `find_symbol` 核对符号 |
| 编译失败看不懂 | `parse_build_errors`、`explain_build_error` |
| 外设寄存器值看不懂 | `svd_list` / `svd_decode`（自动按工程器件推断 SVD） |
| 读到的内存值可疑 | `cache_info`（H7 D-Cache 直读可能是旧值）、`snapshot_diff` 对比 |
| Keil 弹了模态框卡住 | `dismiss_dialog`、`keil_health` |
| 烧进去跑不起来 / 反复复位 | `watch_reset`（复位循环识别，`flags_addr` 给出芯片复位标志寄存器可坐实有没有复位）、`watchdog_freeze`（先冻住看门狗再复现）。注意 Keil 的 `reset` 命令**不产生真实复位**（DWT CYCCNT 不归零、`RCC_CSR` 不置新标志），用它复现复位现象会白测 |
| 想知道「测试跑到哪些函数/行」 | `coverage_start` → 跑流程 → `coverage_read` / `coverage_stop`（PC 采样，不停目标）。结论读 `unseen`（**没看到**，不是「未覆盖」）；采样器不工作/无符号表时会明确报错，不给一份看着像样的分布 |
| 双核 / 怕看的是另一个核 | `core_info`、`core_list`、`core_select`（Keil 链路只给"不支持 + 怎么办"，不假装切了核） |
| 问能不能抓 ETM 指令级 trace | `trace_etm_probe`（给 `present` 与 `supported` 两个**分开**的答案，并给替代方案）；`trace_guide` 看这台机器上实际有哪些 trace 手段 |
| 要改 .sct / 校验分散加载文件 | `scatter_read` → `scatter_check` → `scatter_edit`（改前备份、改后重解析校验，校验不过不落盘） |
| 想看任务切换 / 上下文切换的完整过程 | `trace_instrument(backend="buff")` 插桩 → 跑 → `trace_buff_dump`（全速录不停目标、10ns 粒度）。读回全 0 是「没读到」不是「没有」，先 `stop` |
| 想看异常为什么死 | 在 handler 第一条指令放 `MDK_TRACE_FAULT_CAPTURE()`，事后 `trace_buff_dump` 拿 PC/LR/SP/xPSR + CFSR 分位 |
| 想等「某件事发生」而不是一页一页翻事件 | `trace_watch(action="wait", spec="sync,obj=cond,op=wait")`（手动插桩与自动钩子共用一套条件）；不确定条件写没写对先 `action="test"` 预检 |
| 要给人看波形/时间线/排名（不想手写网页） | `view_render(data_file=..., view="auto")`；不知配哪张图先 `view_guide(topic="views")` |

## 八、一条总原则

**宁可报错，也不给「看似权威的错答案」**：信息不足时这些工具会明确报错、返回
`available: false` 或标注低置信（`matched_by` / `pc_confidence` / `conflict` 之类），
并且**不会替你猜**一个像样的结果。看到这类字段时，照它的 `hint` 补齐证据再下结论。
