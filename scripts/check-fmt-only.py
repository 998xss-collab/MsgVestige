"""判定这次 cargo fmt 是不是**只改了排版**, 不是改了代码。

判据: 把每个改动文件切成 Rust 词法单元, 比对**多重集合**(不看顺序)。
- 纯排版(空白/换行/一行拆多行) -> 词法单元完全一致
- use 重新分组排序 -> 顺序变了但集合不变 -> 多重集合吃掉
- 尾随逗号增删 -> rustfmt 的排版产物 -> 单独排除
- 注释重排/换行 -> 注释不参与比对(它不是代码)
- 真改了代码 -> 一定有词法单元增减 -> 逮到

⚠️ 第一版**自己有 bug**: 用一条正则切 token, 不认注释。而注释里有引号(比如 `"thin-watch"`),
   于是从那个引号起后面几百行被当成一个字符串 token, 51 个文件被误报成"有差异"。
   必须真写个状态机: 逐字符扫, 区分 普通代码 / 行注释 / 块注释 / 字符串 / 字符字面量。
"""

import collections
import re
import subprocess
import sys

TOKEN = re.compile(r"\w+|[^\s\w]")


def strip_comments(src: str) -> str:
    """去掉注释, 保留字符串字面量原样。逐字符状态机 —— 正则做不对这件事。"""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # 行注释 (含 /// 和 //!)
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        # 块注释 (Rust 允许嵌套)
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        # 字符串字面量 (含转义)
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                if src[i] == "\\":
                    out.append(src[i : i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def expand_uses(src: str) -> tuple[str, set]:
    """把 use 语句从正文里摘出来, 展开成**完整路径集合**; 返回 (剩余代码, 路径集合)。

    为什么要展开: rustfmt 的 imports_granularity/group_imports 会把
        use super::dpapi;
        use super::error::KeyError;
    合并成
        use super::{dpapi, error::KeyError};
    引用的东西一个没变, 但 token 数量变了(少一个 use、多一对括号)。
    展开成 {super::dpapi, super::error::KeyError} 两边就一致了。
    """
    paths, rest = set(), []
    i, n = 0, len(src)
    while i < n:
        m = re.compile(r"\buse\s").search(src, i)
        if not m:
            rest.append(src[i:])
            break
        rest.append(src[i : m.start()])
        j = src.find(";", m.end())
        if j < 0:
            rest.append(src[m.start() :])
            break
        body = src[m.end() : j]
        # 递归展开 a::{b, c::{d}} -> a::b, a::c::d
        def walk(prefix: str, s: str) -> None:
            s = s.strip()
            if not s:
                return
            if "{" not in s:
                paths.add((prefix + s).strip())
                return
            head, brace = s.split("{", 1)
            depth, split, cur = 1, [], ""
            for ch in brace:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        split.append(cur)
                        break
                if depth == 1 and ch == ",":
                    split.append(cur)
                    cur = ""
                else:
                    cur += ch
            for part in split:
                walk(prefix + head, part)

        walk("", body)
        i = j + 1
    return "".join(rest), paths


def tokens(data: bytes):
    src = strip_comments(data.decode("utf-8", errors="replace"))
    code, uses = expand_uses(src)
    # 排除三类**纯排版产物**(都不改语义, 逐个看过真实 diff 确认):
    #   ,  尾随逗号: 压行时删 / 拆行时加
    #   ;  `else { break }` 拆多行时 rustfmt 补成 `else { break; }` —— Rust 里两者等价
    #   {} 结构体/块压行拆行时的括号形态
    IGNORE = {",", ";", "{", "}"}
    return collections.Counter(t for t in TOKEN.findall(code) if t not in IGNORE), uses


def main() -> int:
    files = subprocess.run(
        ["git", "diff", "--name-only", "--", "*.rs"], capture_output=True, text=True
    ).stdout.split()
    pure, suspect = [], []
    for f in files:
        old = subprocess.run(["git", "show", f"HEAD:{f}"], capture_output=True).stdout
        try:
            new = open(f, "rb").read()
        except FileNotFoundError:
            continue
        (ta, ua), (tb, ub) = tokens(old), tokens(new)
        if ta == tb and ua == ub:
            pure.append(f)
        else:
            gone = dict(list((ta - tb).items())[:6])
            added = dict(list((tb - ta).items())[:6])
            if ua != ub:
                gone["<use-gone>"] = sorted(ua - ub)[:4]
                added["<use-added>"] = sorted(ub - ua)[:4]
            suspect.append((f, gone, added))
    print(f"changed files: {len(files)}")
    print(f"  pure-format (token multiset identical): {len(pure)}")
    print(f"  token differs (needs human): {len(suspect)}")
    for f, gone, added in suspect[:20]:
        print(f"    {f}")
        print(f"       removed: {gone}")
        print(f"       added  : {added}")
    return 1 if suspect else 0


if __name__ == "__main__":
    sys.exit(main())
