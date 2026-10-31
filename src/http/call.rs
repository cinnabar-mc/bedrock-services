//! One monotonic budget for service preparation, nested acquisition, retries and response reads.

use crate::Error;
use std::{future::Future, time::Duration};
use tokio::time::Instant;

pub(crate) const TIMEOUT: Duration = Duration::from_secs(40);
tokio::task_local! { static DEADLINE: Instant; }

/// Borrows the enclosing call's cutoff without keeping state on a reusable HTTP owner.
pub(crate) fn deadline() -> Option<Instant> {
    DEADLINE.try_with(|deadline| *deadline).ok()
}

/// Bounds the complete call; nested service calls inherit its cutoff and cancellation drops all work.
pub(crate) fn run<T, E: From<Error>>(
    operation: impl Future<Output = Result<T, E>>,
) -> impl Future<Output = Result<T, E>> {
    let operation = Box::pin(operation);
    async move {
        let deadline = deadline().unwrap_or_else(|| Instant::now() + TIMEOUT);
        if Instant::now() >= deadline {
            return Err(E::from(Error::DeadlineExceeded));
        }
        DEADLINE
            .scope(deadline, async {
                tokio::time::timeout_at(deadline, operation)
                    .await
                    .map_err(|_| E::from(Error::DeadlineExceeded))?
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Work prepared after the parent cutoff must not enter another service operation.
    #[tokio::test(start_paused = true)]
    async fn expired_parent_does_not_dispatch_nested_work() {
        let mut dispatched = false;
        let result: Result<(), Error> = run(async {
            tokio::time::advance(TIMEOUT).await;
            run(async {
                dispatched = true;
                Ok(())
            })
            .await
        })
        .await;
        assert!(matches!(result, Err(Error::DeadlineExceeded)));
        assert!(!dispatched);
    }

    /// A nested acquisition cannot restart the budget after expensive request preparation.
    #[tokio::test(start_paused = true)]
    async fn nested_preparation_and_body_share_the_original_cutoff() {
        let started = Instant::now();
        let result: Result<(), Error> = run(async {
            tokio::time::advance(Duration::from_secs(25)).await;
            run(std::future::pending::<Result<(), Error>>()).await
        })
        .await;
        assert!(matches!(result, Err(Error::DeadlineExceeded)));
        assert_eq!(Instant::now() - started, TIMEOUT);
        assert!(deadline().is_none());
    }

    /// Dropping an admitted call leaves no deadline in its caller or next service operation.
    #[tokio::test(start_paused = true)]
    async fn canceled_scope_does_not_leak_into_the_next_call() {
        {
            let pending = run(std::future::pending::<Result<(), Error>>());
            tokio::pin!(pending);
            std::future::poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert!(deadline().is_none());
        let result: Result<(), Error> = run(async {
            tokio::time::advance(Duration::from_secs(35)).await;
            Ok(())
        })
        .await;
        result.unwrap();
    }
}
