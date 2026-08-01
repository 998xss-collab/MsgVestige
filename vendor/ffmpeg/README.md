# vendored ffmpeg (wxgf 动图/HEVC 图 → PNG/GIF 转码)

`native-cli decrypt-images --full-images` 把微信 **wxgf** 图 (V2 完整图内层, HEVC 编码) 转成可看的图时调这里的 `ffmpeg.exe`。**不碰微信闭源 dll** (VoipEngine.dll) —— 纯 ffmpeg 软件解码路 (同竞品 chatlog)。

## 二进制 (不进 git, 见 `/.gitignore`)

| 文件 | 说明 |
|---|---|
| `ffmpeg.exe` | 转码主程序 (~97MB, 静态构建, 内含 HEVC 解码器) |
| `ffprobe.exe` | 探帧数 (静图→PNG 无损 / 动图→GIF) |

**为何不进 git**: ~97MB 静态构建, 进 git 会把仓库/历史撑爆。改为**打包时随产品分发** (放 msgvestige.exe 同目录或本 `vendor/ffmpeg/`)。删本目录即无残留 —— 不装系统、不动 PATH/注册表。

## 来源 (复现)

- 版本: **ffmpeg 8.1.2-essentials_build** (gyan.dev)
- 下载: <https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip> (解压后 `bin/ffmpeg.exe` + `bin/ffprobe.exe`)
- PowerShell 一键取:
  ```powershell
  $z="$env:TEMP\ffmpeg.zip"
  Invoke-WebRequest "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip" -OutFile $z
  Expand-Archive $z "$env:TEMP\ffmpeg_x" -Force
  Copy-Item (gci "$env:TEMP\ffmpeg_x" -Recurse -Filter ffmpeg.exe).FullName  "$PSScriptRoot\ffmpeg.exe"
  Copy-Item (gci "$env:TEMP\ffmpeg_x" -Recurse -Filter ffprobe.exe).FullName "$PSScriptRoot\ffprobe.exe"
  ```

## 代码怎么找它 (native-cli `resolve_ffmpeg`)

依次: `--ffmpeg <路径>` → 环境变量 `WECHAT_FFMPEG` → **cli 可执行同目录** `ffmpeg[.exe]` / `ffmpeg/ffmpeg[.exe]` → 系统 `PATH`。都没有 → wxgf 留 `.wxgf` 不转 (内容不丢, 装了再重跑)。`ffprobe` 从 `ffmpeg` 同目录找。

## 许可

gyan.dev essentials 构建含 GPL 组件。本项目**以子进程调用** ffmpeg (不静态链接) —— 内部/自用 (跨自己电脑) 无碍; 若对外分发含本二进制的包, 按 GPL 履行义务 (附源码获取途径)。许可判断归项目方。
