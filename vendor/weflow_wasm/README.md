# vendored weflow_wasm — 微信 WxIsaac64 keystream (朋友圈媒体解密, ADR-467 件3)

朋友圈 CDN 媒体 (图/视频) 加密用微信的 **WxIsaac64** keystream 全文/前128KB XOR。该算法**不是标准 ISAAC64**
(实测公开 python/TS 实现均对不上, 见 ADR-467 §11 调研), 只在微信/WeFlow 编译的 WASM 黑盒里对 → 必须
spawn `node` 跑本目录脚本生成 keystream。**运行期依赖系统 node** (换机器需装; 用户拍板『全支持·环境不自带』)。

## 文件 (不进 git; 打包随产品分发)
- `wasm_video_decode.wasm` (3.6MB) — 微信/WeFlow 编译的 Emscripten+embind+FFmpeg WASM, 内含 WxIsaac64。
- `wasm_video_decode.js` (0.17MB) — Emscripten JS glue (加载 + 运行 WASM)。
- `weflow_wasm_keystream.js` — 薄封装: `node weflow_wasm_keystream.js <key> <size>` → stdout base64 keystream
  (脚本内已对齐/反转/截断)。

## 来源
从竞品 WeChatDataAnalysis 的 `src/wechat_decrypt_tool/native/weflow_wasm/` 原样拷入 (WeFlow 项目产物)。
CipherTalk `electron/assets/wasm/wasm_video_decode.wasm` 同款。复现: 从这些开源竞品仓库取对应 3 文件。

## 用法 (native-cli)
```
native-cli export-sns-media --l1-db <L1> --out-dir <dir> --limit N --wasm-dir <本目录>
```
cli 缺省依次找 `--wasm-dir` → `WECHAT_SNS_WASM_DIR` → cli 同目录 `vendor/weflow_wasm`。

## 为何不纯 Rust
标准 ISAAC64 (RustCrypto/公开实现) 对不上微信变体 (真图解出乱码, ADR-467 §11 实测 8 种字节序组合 + WDA python
+ CipherTalk TS 均失败)。逆 3.6MB FFmpeg WASM 不现实 → 同语音 SILK 走 vendored 黑盒。**本地缓存图 (`cache/*/Sns/Img`
的 V2 .dat) 才是纯 Rust 路** (decoder/dat.rs 已实现, 但只覆盖已看过的图; 本件走 CDN 覆盖全部媒体)。
