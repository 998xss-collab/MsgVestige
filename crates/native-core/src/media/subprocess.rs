//! 媒体子进程有界执行 (ffmpeg 转码 / node keystream): **超时 kill + stdout 上限** —— media §8 逮到的 P2:
//! 子进程 (对不可信/病态媒体解码炸弹) 无超时会永久占死共享 MEDIA_SEMAPHORE(serve 全 /media DoS) + stdout 无界
//! 缓冲爆内存。这里统一加 deadline (同 exec 的 15s progress 界) + stdout 截断, 令 permit 持有时间有界、恢复自愈。

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt as _;

/// 跑子进程只取**退出成功与否** (输出落文件/丢弃; ffmpeg 转码、`-version` 探活用)。超时 → kill + `false`。
/// spawn 失败 / 非零退出 / 超时 一律 `false`。
#[must_use]
pub fn status_with_timeout(mut cmd: Command, timeout: Duration) -> bool {
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => status.success(),
        _ => {
            // 超时 / wait 出错 → kill + 回收 (不留孤儿进程)。
            let _ = child.kill();
            let _ = child.wait();
            false
        }
    }
}

/// 跑子进程取 **stdout** (ffprobe 帧数、node keystream 用)。超时 → kill + `None`; stdout 上限 `max_bytes` 防无界缓冲。
///
/// stdout 用**独立线程边跑边读** (大输出撑满管道会死锁 wait), 读满 `max_bytes` 即停 —— 子进程继续写会阻塞在满管道,
/// 由 `wait_timeout` 到期 kill 兜底。返回子进程成功退出时读到的 stdout (≤ max_bytes); 非零退出 / 超时 / spawn 失败 → `None`。
#[must_use]
pub fn output_with_timeout(mut cmd: Command, timeout: Duration, max_bytes: u64) -> Option<Vec<u8>> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        // 上限截断: 超 max_bytes 不再读 (子进程写满管道阻塞 → wait_timeout kill)。
        let _ = stdout.take(max_bytes).read_to_end(&mut buf);
        buf
    });
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => {
            // 子进程正常退出 → 管道写端已关, reader.read_to_end 立即返回, join 不阻塞。
            let buf = reader.join().ok()?;
            status.success().then_some(buf)
        }
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            // **不 join reader**: 被 kill 的子进程若有 grandchild 继承了管道写端 (如 cmd→ping), read_to_end 会
            // 阻塞到 grandchild 退出 → join 卡住。detach 让 reader 自行收尾 (生产的 node/ffprobe 无此 grandchild,
            // kill 即关管道秒退; 有则线程短暂存活不阻塞调用方)。
            drop(reader);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const SLEEP_CMD: (&str, &[&str]) = ("cmd", &["/C", "ping 127.0.0.1 -n 30 >NUL"]);
    #[cfg(not(windows))]
    const SLEEP_CMD: (&str, &[&str]) = ("sh", &["-c", "sleep 30"]);

    #[test]
    fn status_timeout_kills_hung_child() {
        let mut cmd = Command::new(SLEEP_CMD.0);
        cmd.args(SLEEP_CMD.1);
        let t0 = std::time::Instant::now();
        let ok = status_with_timeout(cmd, Duration::from_millis(400));
        assert!(!ok, "挂死子进程超时 → false");
        assert!(t0.elapsed() < Duration::from_secs(5), "确实被 kill 未等满 30s");
    }

    #[test]
    fn status_bad_binary_is_false() {
        let cmd = Command::new("definitely-not-a-real-binary-xyz");
        assert!(!status_with_timeout(cmd, Duration::from_secs(2)), "spawn 失败 → false");
    }

    #[test]
    fn output_timeout_kills_and_none() {
        let mut cmd = Command::new(SLEEP_CMD.0);
        cmd.args(SLEEP_CMD.1);
        let t0 = std::time::Instant::now();
        assert!(
            output_with_timeout(cmd, Duration::from_millis(400), 1024).is_none(),
            "挂死 → None"
        );
        assert!(t0.elapsed() < Duration::from_secs(5), "被 kill 未等满");
    }
}
