//! A bounded-concurrency worker pool.
//!
//! The scan runs many independent probes, but a scope caps how many may be in flight at
//! once. [`WorkerPool::run`] drives a set of futures with at most `concurrency` running
//! simultaneously and returns their results in the original input order.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Runs futures with bounded concurrency.
#[derive(Debug, Clone)]
pub struct WorkerPool {
    concurrency: usize,
}

impl WorkerPool {
    /// A pool allowing `concurrency` simultaneous tasks (minimum 1).
    pub fn new(concurrency: usize) -> Self {
        WorkerPool {
            concurrency: concurrency.max(1),
        }
    }

    /// The configured concurrency limit.
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Run `tasks`, at most `concurrency` at a time, returning results in input order.
    pub async fn run<T, Fut>(&self, tasks: Vec<Fut>) -> Vec<T>
    where
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let n = tasks.len();
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let mut set: JoinSet<(usize, T)> = JoinSet::new();
        for (i, fut) in tasks.into_iter().enumerate() {
            let sem = sem.clone();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("semaphore open");
                (i, fut.await)
            });
        }
        let mut slots: Vec<Option<T>> = (0..n).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (i, value) = joined.expect("task did not panic");
            slots[i] = Some(value);
        }
        slots.into_iter().map(|s| s.expect("every slot filled")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn results_are_returned_in_input_order() {
        let pool = WorkerPool::new(4);
        let tasks: Vec<_> = (0..10)
            .map(|i| async move {
                // reverse the natural completion order a little
                tokio::time::sleep(std::time::Duration::from_millis((10 - i) as u64)).await;
                i * 2
            })
            .collect();
        let out = pool.run(tasks).await;
        assert_eq!(out, (0..10).map(|i| i * 2).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        let pool = WorkerPool::new(3);
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let live = live.clone();
                let peak = peak.clone();
                async move {
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    live.fetch_sub(1, Ordering::SeqCst);
                }
            })
            .collect();
        pool.run(tasks).await;
        assert!(peak.load(Ordering::SeqCst) <= 3, "peak was {}", peak.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn empty_task_list_is_fine() {
        let pool = WorkerPool::new(2);
        // An empty, but concretely-typed, set of futures.
        let tasks: Vec<_> = (0..0).map(|_| async { 0i32 }).collect();
        let out = pool.run(tasks).await;
        assert!(out.is_empty());
    }
}
