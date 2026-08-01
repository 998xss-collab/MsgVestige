#!/usr/bin/env python3
"""随包文档的机械体检 —— 只查「文本层面坏没坏」, 不查内容对不对。

**为什么有这个脚本**: 第三轮审查逮到一条**物理上敲不出来的命令** —— `.\\msgvestige.exe`
里的反斜杠变成了真的换行字节 (`60 2e 0a 61` = 反引号 + 点 + 换行 + "sgvestige.exe")。
根因是我用 Python 脚本批量改文档时转义漏了一层。这类损坏靠肉眼读几乎发现不了
(渲染出来只是"换了行"), 但用户照着敲一定失败, 而文档开头还承诺"每条命令都真跑过"。

既然改文档要一直用脚本, 就得有一道机器闸。**每次改完随包文档跑一遍这个。**

用法:  python scripts/check-docs.py [文件...]
       不给参数就查默认那几份随包文档。
退出码: 0 = 干净, 1 = 有问题 (逐条打印)。
"""

import re
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_DOCS = ["docs-dev/快速开始.md", "docs-dev/00-当前生效/数据可见性矩阵.md"]

# 命令行程序名 —— 用来认出"被换行截断的命令"。
EXES = ["msgvestige.exe", "msgvestige-adapter.exe"]


def check(path: Path) -> list[str]:
    """返回问题清单 (空 = 干净)。"""
    problems: list[str] = []
    raw = path.read_bytes()
    text = raw.decode("utf-8")

    def bad(msg: str) -> None:
        problems.append(f"{path.name}: {msg}")

    # ① 转义事故 —— 三轮那条 P1 的直接判据。
    #    `\n` 被吃掉后, 程序名会从中间断开: "…`." + 换行 + "sgvestige.exe"。
    #    对每个 exe 名, 逐个前缀长度找"换行 + 该名的后缀"。
    for exe in EXES:
        for cut in range(1, len(exe)):
            frag = "\n" + exe[cut:]
            for m in re.finditer(re.escape(frag), text):
                line = text[: m.start()].count("\n") + 1
                bad(f"第 {line} 行后疑似转义事故 — 换行后紧跟 {exe!r} 的后缀 {exe[cut:]!r}")
    # 反向: 行尾是孤零零的 "`." 或 "." 且下一行以小写字母开头接 "-cli.exe"
    if re.search(r"`\.\n[a-z]", text):
        bad("有行以 '`.' 结尾且下一行以小写字母开头 — 典型的反斜杠被吃成换行")

    # ② 不该出现的字符。
    for name, pat in [
        ("制表符", "\t"),
        ("不换行空格 NBSP", " "),
        ("零宽字符", "​"),
        ("BOM", "﻿"),
        ("全角空格", "　"),
    ]:
        n = text.count(pat)
        if n:
            bad(f"含 {n} 个{name} — 复制粘贴命令时会出问题")
    if b"\r\n" in raw:
        bad("含 CRLF 换行 — 随包文档统一用 LF")

    # 引用块里也能放代码围栏 (`> ```)。**认围栏前先剥掉行首的 `>` 和空白** ——
    # 不剥的话那些围栏认不出来, 它们的三个反引号会被下面的"行内反引号奇偶"当成没闭合。
    # (第一版就是这样, 一跑六个误报。带误报的检查没人会看, 等于没有。)
    def strip_quote(line: str) -> str:
        out = line
        while out.lstrip().startswith(">"):
            out = out.lstrip()[1:]
        return out.strip()

    def is_fence(line: str) -> bool:
        return strip_quote(line).startswith("```")

    # ③ 代码围栏配对。奇数 = 有块没闭合, 后面全被吞进代码块。
    fences = [i for i, l in enumerate(text.split("\n"), 1) if is_fence(l)]
    if len(fences) % 2:
        bad(f"代码围栏 ``` 有 {len(fences)} 个 (奇数) — 有块没闭合; 行号 {fences}")

    # ④ 行内反引号配对 (按行看; 代码块内不算)。
    in_block = False
    for i, line in enumerate(text.split("\n"), 1):
        if is_fence(line):
            in_block = not in_block
            continue
        if in_block:
            continue
        # 去掉 ``双反引号`` 这种少见写法再数
        if line.count("`") % 2:
            bad(f"第 {i} 行反引号是奇数个 — 行内 code 没闭合: {line.strip()[:60]}")

    # ④b 围栏外的行尾空格 / 只有 "> " 的空引用行。
    #
    # **第四轮审查逮到的**: 引用块中间夹了一行只有 "> " 加一个尾空格的空行, 把一句话从逗号处
    # 劈成了两个段落 (markdown 里空引用行 = 段落分隔), 渲染出来前半句以逗号悬空结尾。
    # 上一版这个脚本**没查这个**, 所以漏了 —— 跟"反斜杠变换行"同一类: 脚本批改留下的、
    # 肉眼几乎看不出的文本损坏。行尾空格本身在 markdown 里还有"硬换行"的含义, 更该显式管。
    in_block = False
    for i, line in enumerate(text.split("\n"), 1):
        if is_fence(line):
            in_block = not in_block
            continue
        if in_block or not line:
            continue
        if line != line.rstrip():
            kind = "只有 '>' 的空引用行" if line.strip() in (">", "") else "行尾多余空格"
            bad(f"第 {i} 行{kind} (markdown 里会变成段落分隔/硬换行): {line.rstrip()[:50]!r}+空格")

    # ⑤ 表格列数一致 (同一张表里每行 | 的个数应相同)。
    in_block = False
    table: list[tuple[int, int, str]] = []
    for i, line in enumerate(text.split("\n") + [""], 1):
        if is_fence(line):
            in_block = not in_block
            continue
        if in_block:
            continue
        stripped = line.strip()
        is_row = stripped.startswith("|") and stripped.endswith("|")
        if is_row:
            table.append((i, stripped.count("|"), stripped))
        elif table:
            counts = {c for _, c, _ in table}
            if len(counts) > 1:
                detail = ", ".join(f"第{ln}行{c}个" for ln, c, _ in table)
                bad(f"表格列数不一致 ({detail})")
            table = []

    # ⑥ 提取每条命令, 看是不是完整一行。
    for i, line in enumerate(text.split("\n"), 1):
        for exe in EXES:
            if exe not in line:
                continue
            # 命令应当以 .\ 或 ./ 或行首程序名出现, 且后面跟着子命令
            for m in re.finditer(re.escape(exe) + r"(.*)$", line):
                rest = m.group(1).strip()
                if not rest:
                    continue
                if rest.startswith("`") or rest.startswith("**") or rest.startswith(")"):
                    continue  # 是叙述里提到程序名, 不是命令
                head = rest.split()[0] if rest.split() else ""
                if head.startswith("-") and head not in ("--help", "--version"):
                    bad(f"第 {i} 行: {exe} 后面直接跟了 {head} — 少了子命令?")

    # ⑦ 超宽行 (CJK 算 2 列) —— 记事本 / 窄终端里会糊。只报正文, 代码块放过。
    def width(s: str) -> int:
        return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)

    in_block = False
    wide: list[int] = []
    for i, line in enumerate(text.split("\n"), 1):
        if is_fence(line):
            in_block = not in_block
            continue
        if in_block:
            continue
        stripped = line.strip()
        # **表格行豁免**: markdown 的表格行物理上折不了行 (一折就不是表了), 报了也改不掉,
        # 这道闸就永远过不去 —— 过不去的闸等于没有闸, 只会被人加 --skip 绕过。
        # 宽表在记事本里确实糊, 但那是"要不要用表"的取舍, 不是机械损坏, 不归这个脚本管。
        if stripped.startswith("|") and stripped.endswith("|"):
            continue
        if width(line) > 120:
            wide.append(i)
    if wide:
        bad(f"正文有 {len(wide)} 行超过 120 列 (行号 {wide}) — 记事本里会折行糊掉, 手动折一下")

    return problems


def main() -> int:
    # Windows 控制台默认 GBK, 打 emoji 会 UnicodeEncodeError 直接崩 —— 崩了就等于没查,
    # 而且是"工具自己坏了"伪装成"跑不了"。强制 stdout 用 UTF-8 并对打不出的字符降级,
    # 保证在别人机器上也能跑出结论。(实测: 不加这段, 本机跑第一行就崩。)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    targets = sys.argv[1:] or DEFAULT_DOCS
    all_problems: list[str] = []
    for t in targets:
        p = REPO / t if not Path(t).is_absolute() else Path(t)
        if not p.is_file():
            all_problems.append(f"{t}: 找不到这个文件")
            continue
        found = check(p)
        print(f"{'✅' if not found else '🛑'} {p.name}: {len(found)} 个问题")
        all_problems += found
    for m in all_problems:
        print("  -", m)
    return 1 if all_problems else 0


if __name__ == "__main__":
    sys.exit(main())
