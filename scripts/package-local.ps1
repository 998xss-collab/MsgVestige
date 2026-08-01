# 本地打包 —— 出一个可分发的压缩包, 并当场验它能跑。
#
# 为什么有这个脚本: 仓库目前**没有远程**(`git remote -v` 为空), 所以 `.github/workflows/release.yml`
# 永远不会被执行。要拿到包只能本地打。将来仓库推上去了, 那个 workflow 才生效 —— 两边做的是同一件事,
# 改了一边记得同步另一边(这是已知的重复, 没有更好的办法, 除非把步骤抽成脚本让 workflow 也调它)。
#
# 用法:  pwsh -File scripts/package-local.ps1 [-Version v0.1.0-alpha.1]

# -Full: 连同 ffmpeg / node / weflow_wasm 一起打进去 —— 对方**什么都不用装**。
#        代价是包从 ~9MB 涨到 ~150MB(主要是 ffmpeg 和 node)。
# 不加 -Full: 精简版, 只有主程序; 那三样是可选功能, 缺了不影响主路径。
param([string]$Version = "dev", [switch]$Full)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

Write-Host "=== 1/4 编译(静态链 CRT)===" -ForegroundColor Cyan
# +crt-static: 不静态链的话产物依赖 VCRUNTIME140.dll —— 那是 VC++ 可再发行组件, **不是系统自带**,
# 没装的机器上双击就报缺 DLL。--locked: 必须用提交进仓库的那份 Cargo.lock。
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release --locked --bin msgvestige --bin msgvestige-adapter --target-dir target-static
if ($LASTEXITCODE -ne 0) { throw "编译失败" }
$env:RUSTFLAGS = $null

Write-Host "=== 2/4 组装 ===" -ForegroundColor Cyan
$flavor = if ($Full) { "full" } else { "slim" }
$stage = Join-Path $repo "dist/msgvestige-wechat-$Version-windows-x64-$flavor"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item target-static/release/msgvestige.exe     $stage/
Copy-Item target-static/release/msgvestige-adapter.exe $stage/
# ⚠️ **README.md / INSTALL.md 故意不进包** —— 它俩会误导拿到包的人:
#   README.md 是仓库的**内部需求文档**索引(开头就写着「状态: 需求确认中(不是开发文档)」),
#     满篇 ADR 编号和 §11.5 引用, 对方打开一头雾水。
#   INSTALL.md 描述的是**已退役的 sidecar 架构**: 说 zip 里含 sidecar-bundle (Node + Electron +
#     wcdb_api.dll) + vendor/wx_key.dll —— 本包一个都没有; 让人跑 `msgvestige migrate-config`
#     —— 这命令不存在(实测); 说 auth 要「重新登录微信触发 hook」—— 跟推荐的 `auth --scan`
#     (不动微信) 正相反。发一份自相矛盾的文档比不发更糟。
#   它俩仍留在仓库里(各有各的用处), 只是不进发布包。真正给用户看的是下面这份快速开始。
# **排第一位的是快速开始** —— 对方解压后最该先看这份(三条命令 + 每条的真实输出 + 卡住了怎么办)。
# 里面每条命令和每段输出都是真机跑出来的, 不是照帮助文本编的。
Copy-Item "docs-dev/快速开始.md" $stage/
# 第二个问题是「这东西能给我拿到什么」, 答案在这份。
Copy-Item "docs-dev/00-当前生效/数据可见性矩阵.md" $stage/

if ($Full) {
    Write-Host "  -Full: 内置 ffmpeg / node / weflow_wasm"
    New-Item -ItemType Directory -Force (Join-Path $stage "vendor") | Out-Null
    # ffmpeg: 语音导 mp3 用。195MB, 精简版故意不带。
    Copy-Item -Recurse (Join-Path $repo "vendor/ffmpeg") (Join-Path $stage "vendor") -Force
    # weflow_wasm: 朋友圈媒体取流用。
    Copy-Item -Recurse (Join-Path $repo "vendor/weflow_wasm") (Join-Path $stage "vendor") -Force
    # node: 跑上面那个 wasm 要它。**只要 node.exe 一个文件**(87MB), 不用整个 nodejs 安装目录(103MB)
    # —— 实测单个 node.exe 能 WebAssembly.compile 那个 wasm。
    $node = (Get-Command node -ErrorAction SilentlyContinue).Source
    if (-not $node) { throw "-Full 需要本机装了 node(要把 node.exe 打进包), 但找不到" }
    Copy-Item $node (Join-Path $stage "vendor/node.exe") -Force
}

$whatIsIn = if ($Full) { @"

- vendor/ffmpeg/ —— 语音导出成 mp3 用。
- vendor/weflow_wasm/ + vendor/node.exe —— 朋友圈媒体取流用(node.exe 已内置, 不用另装)。
"@ } else { "" }
$whatIsNotIn = if ($Full) { @"

(这是**完整版**, 该带的都带了。)
"@ } else { @"

- **ffmpeg**(195MB, 故意不带)。只用于把语音导出成 mp3; 不带的话默认导 wav, 其余功能不受影响。
  要 mp3: 自己下一份 ffmpeg.exe/ffprobe.exe 放到 vendor/ffmpeg/, 或用 --ffmpeg 指到你的那份。
- **weflow_wasm + node**(朋友圈媒体取流用)。需要的话装 node 并从源仓库取 vendor/weflow_wasm/。
- **wx_key.dll**(取 key 的一条**可选回退**路径)。没有它不影响主路径 —— 默认的纯 Rust 取 key 走得通。

上面前两样用**完整版**(包名带 -full), 里面都带上了。
**wx_key.dll 两个版本都不带** —— 它的真身没进代码仓库, 打包时拿不到。默认取 key 路径不需要它。
"@ }

@"
# 这个包里有什么

- **快速开始.md —— 先看这个。** 三条命令跑通全流程, 每条都带真实输出, 附常见报错的解法。
- msgvestige.exe / msgvestige-adapter.exe —— 主程序, **解压即用**, 不依赖任何非系统 DLL(静态链了 CRT)。
- 数据可见性矩阵.md —— **能拿到什么**: 12 类数据逐类记「能不能拿到 / 从哪条路拿 / 拿不到卡在哪」,
  每一格都是真库跑出来的, 不是照代码推断。装完先看这份。$whatIsIn

# 这个包里**没有**什么
$whatIsNotIn

# 先跑这个确认包是好的

.\msgvestige.exe --version
"@.Replace("`r`n", "`n") | Set-Content -Encoding UTF8 -NoNewline (Join-Path $stage "包内清单.md")
# ⚠️ 换行归一成 LF: PowerShell 的 here-string 在这个文件里会混出 CRLF 和 LF 两种
#    (审查方实测: 包内清单.md 是 1 处 CRLF + 19 处 LF 的混合体, 而同包另两份 md 是纯 LF)。
#    随包三份文档换行不一致, 在有些编辑器里会显示成一坨。-NoNewline 是配合 .Replace 用的:
#    Set-Content 默认还会再补一个平台换行, 那样又混回去了。

$zip = Join-Path $repo "dist/msgvestige-wechat-$Version-windows-x64-$flavor.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip

Write-Host "=== 3/4 验包(解压到干净目录, 跑解出来的那个 exe)===" -ForegroundColor Cyan
# 只验 "workflow 绿了" 等于 CI 自己说自己好 —— 这里跑的是**压缩包解出来的**产物, 且换目录跑,
# 保证不靠仓库里的任何东西。
$tmp = Join-Path ([IO.Path]::GetTempPath()) "pkgverify-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
Expand-Archive -Path $zip -DestinationPath $tmp
Push-Location $tmp
try {
    ./msgvestige.exe --version
    if ($LASTEXITCODE -ne 0) { throw "解压后的 msgvestige --version 跑不起来" }
    ./msgvestige.exe messages --help > $null
    if ($LASTEXITCODE -ne 0) { throw "messages --help 跑不起来" }
    ./msgvestige-adapter.exe --help > $null 2>&1
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) { throw "msgvestige-adapter 跑不起来(退出码 $LASTEXITCODE)" }

    # 断言不依赖任何非系统 DLL —— **真读 PE 导入表**, 不在文件里做字符串匹配(那样会被普通字符串误报),
    # 也不靠 dumpbin 加人肉过滤(那样容易把要找的东西过滤掉)。
    $sysDlls = @('kernel32','ntdll','advapi32','ws2_32','oleaut32','shell32','psapi','crypt32',
                 'bcryptprimitives','pdh','powrprof','user32','ole32','combase','shlwapi','userenv',
                 'secur32','bcrypt','gdi32','comctl32','ucrtbase','msvcrt','iphlpapi','dnsapi',
                 'winmm','version','rpcrt4','dbghelp','setupapi','comdlg32','cfgmgr32','shcore',
                 'winhttp','wininet','imm32','uxtheme','oleacc','propsys','windowscodecs')
    foreach ($exe in @('msgvestige.exe','msgvestige-adapter.exe')) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $tmp $exe))
        $e = [BitConverter]::ToInt32($bytes, 0x3c)
        $nsec = [BitConverter]::ToUInt16($bytes, $e + 6)
        $optSize = [BitConverter]::ToUInt16($bytes, $e + 20)
        $magic = [BitConverter]::ToUInt16($bytes, $e + 24)
        $ddOff = $e + 24 + $(if ($magic -eq 0x20b) { 112 } else { 96 })
        $impRva = [BitConverter]::ToUInt32($bytes, $ddOff + 8)
        $secs = @()
        for ($i = 0; $i -lt $nsec; $i++) {
            $o = $e + 24 + $optSize + 40 * $i
            $secs += , @([BitConverter]::ToUInt32($bytes,$o+12), [BitConverter]::ToUInt32($bytes,$o+8), [BitConverter]::ToUInt32($bytes,$o+20))
        }
        $r2o = { param($rva) foreach ($s in $secs) { if ($rva -ge $s[0] -and $rva -lt $s[0] + [Math]::Max($s[1],1)) { return $s[2] + ($rva - $s[0]) } } ; return -1 }
        $imports = @(); $off = & $r2o $impRva
        while ($off -ge 0) {
            $nameRva = [BitConverter]::ToUInt32($bytes, $off + 12)
            if ($nameRva -eq 0) { break }
            $no = & $r2o $nameRva; if ($no -lt 0) { break }
            $end = $no; while ($bytes[$end] -ne 0) { $end++ }
            $imports += [Text.Encoding]::ASCII.GetString($bytes, $no, $end - $no).ToLower()
            $off += 20
        }
        # 解析不出任何导入项就抛错 —— 否则「解析逻辑坏了」会伪装成「没有依赖」而静默通过。
        if ($imports.Count -eq 0) { throw "$exe 导入表解析不出来(解析逻辑坏了, 不能当成没有依赖)" }
        $bad = $imports | Where-Object { $_ -notmatch '^api-ms-win-' -and $sysDlls -notcontains ($_ -replace '\.dll$','') }
        if ($bad) { throw "$exe 依赖非系统 DLL: $($bad -join ', ')" }
        Write-Host "  $exe 导入 $($imports.Count) 项, 全部是系统 DLL"
    }
} finally { Pop-Location }
# 刚跑过的进程可能还没完全退出, 文件句柄没释放 —— 清理失败不该让整个打包算失败(包已经好了)。
for ($i = 0; $i -lt 5; $i++) {
    try { Remove-Item -Recurse -Force $tmp -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 400 }
}
if (Test-Path $tmp) { Write-Host "  (临时验包目录没删掉, 不影响产物: $tmp)" -ForegroundColor DarkGray }

Write-Host "=== 4/4 完成 ===" -ForegroundColor Green
$size = (Get-Item $zip).Length / 1MB
Write-Host ("包: {0}  ({1:N1} MB)" -f $zip, $size)
Get-ChildItem $stage | ForEach-Object { "  " + $_.Name }
