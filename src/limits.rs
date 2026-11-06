pub const MAX_TARGETS: usize = 65_536;
pub const MAX_WORKERS: usize = 4_096;
/// Automatic sizing never exceeds this.
///
/// Connect-scan throughput peaks between roughly 256 and 1,024 workers on a
/// 12-core machine and degrades sharply above it: 4,096 workers spend most of
/// their time in scheduler and futex waits instead of probing, cutting
/// full-range loopback scans to about a fifth of their achievable rate.
pub const MAX_AUTO_WORKERS: usize = 512;

/// Choose the worker count for this scan.
///
/// `requested == 0` means automatic sizing from `RLIMIT_NOFILE`. In both cases
/// the count is capped and never exceeds the number of jobs.
pub fn worker_count(requested: usize, jobs: u64) -> usize {
    let jobs = usize::try_from(jobs).unwrap_or(usize::MAX).max(1);
    let base = if requested == 0 {
        automatic_worker_target()
    } else {
        requested.min(MAX_WORKERS)
    };
    base.clamp(1, MAX_WORKERS).min(jobs)
}

#[cfg(unix)]
fn automatic_worker_target() -> usize {
    let available = file_limit_target();
    let fd_ceiling = available.saturating_mul(3) / 4;
    let cores = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(4);
    let target = cores.saturating_mul(32).min(fd_ceiling);
    target.clamp(64, MAX_AUTO_WORKERS as u64) as usize
}

#[cfg(not(unix))]
fn automatic_worker_target() -> usize {
    256
}

#[cfg(unix)]
fn file_limit_target() -> u64 {
    // SAFETY: getrlimit and setrlimit only read or write the supplied struct.
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return 1_024;
        }

        let soft = limit.rlim_cur;
        let hard = limit.rlim_max;
        let desired = soft.max(16_384).min(hard);

        if desired > soft {
            let raised = libc::rlimit {
                rlim_cur: desired as libc::rlim_t,
                rlim_max: limit.rlim_max,
            };
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &raised);
        }

        desired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_count_is_bounded_by_jobs_and_cap() {
        assert_eq!(worker_count(1, 0), 1);
        assert_eq!(worker_count(1, 10), 1);
        assert_eq!(worker_count(0, 1), 1);
        assert!(worker_count(0, 1_000_000) >= 64);
        assert!(worker_count(0, 1_000_000) <= MAX_WORKERS);
        assert_eq!(worker_count(MAX_WORKERS + 1, 1_000_000), MAX_WORKERS);
    }

    #[test]
    fn automatic_workers_stay_within_the_auto_cap() {
        let automatic = worker_count(0, 1_000_000);
        assert!(automatic >= 64, "auto target must stay usable: {automatic}");
        assert!(
            automatic <= MAX_AUTO_WORKERS,
            "auto target must avoid the contention collapse: {automatic}"
        );
        assert!(worker_count(0, 200) <= 200, "auto target follows job count");
    }
}
