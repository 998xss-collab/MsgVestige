# Vendored: Skype SILK SDK (C)

微信语音 (SILK v3, 24kHz) 解码用的 C 源码, 原样 vendored 进本 crate。

- **来源**: Skype SILK Speech Codec SDK (C), 经 crates.io [`silk-v3-sys`](https://crates.io/crates/silk-v3-sys) v0.1.0
  ([repo](https://github.com/aispeech-di/silk-v3-sys)) 打包的一份。上游 = Skype Limited 开源的 SILK SDK
  (RFC 6716 SILK 层参考实现之一)。
- **版本**: silk-v3-sys 0.1.0 (2023-05) bundle 的版本; 上游 Skype SDK 版权头标 **2006-2012**。
- **License**: **BSD-3-Clause 风格** (Copyright (c) 2006-2012, Skype Limited)。见每个 `.c`/`.h` 文件头
  Copyright 块 — 允许源码 / 二进制再分发, 须保留版权声明与免责声明。宽松, 可商用。
- **用途**: 解码微信语音消息 (`media_0.db` / `VoiceInfo.voice_data`, SILK v3 24kHz mono 变体) → PCM。
- **本地改动**: **无** (原样 vendored, 未改一行 C)。
- **集成方式**: `../build.rs` 用 `cc` crate 编 `interface/` + `src/` 下所有 `.c` → 静态库, `../src/lib.rs`
  **手写 FFI** 调用 (`SKP_Silk_SDK_Get_Decoder_Size` / `InitDecoder` / `Decode` + `DecControl`)。
  **刻意不用 silk-v3-sys 的 bindgen** → 免编译期 libclang/LLVM 依赖 (换机器最易缺的一环), 可移植性严格更优。
- **同源佐证**: 业界事实标准 [`kn007/silk-v3-decoder`](https://github.com/kn007/silk-v3-decoder) (3.2k★) 本质
  是同一份 Skype SILK SDK C。

## 跨平台 / 审计备注
- C 源码本身跨平台; 将来上 Linux/Mac 由 `cc` 自动选 gcc/clang, 无需改动。
- 升级 / 替换上游时: 保持 `interface/` + `src/` 目录结构 (build.rs 递归收 `.c`), 手写 FFI 的 3 个函数签名
  若上游 API 变则同步 `../src/lib.rs`。
