//! Private bounded transport helpers shared by the two concrete WebSocket edges.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use tokio_websockets::Connector;

/// Limits incomplete HTTP upgrade headers without changing WebSocket framing.
pub(crate) const MAX_UPGRADE_BYTES: usize = 32 * 1024;

/// HTTP parsing has a byte budget; successful upgrade restores ordinary socket reads.
pub(crate) struct UpgradeIo<T> {
    inner: T,
    remaining: Option<usize>,
    #[cfg(test)]
    write_budget: Option<usize>,
    #[cfg(test)]
    write_waker: Option<std::task::Waker>,
}

impl<T> UpgradeIo<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            remaining: Some(MAX_UPGRADE_BYTES),
            #[cfg(test)]
            write_budget: None,
            #[cfg(test)]
            write_waker: None,
        }
    }

    pub(crate) fn upgraded(&mut self) {
        self.remaining = None;
    }

    /// Allows a finite number of bytes before holding test writes Pending.
    #[cfg(test)]
    pub(crate) fn limit_writes(&mut self, bytes: usize) {
        self.write_budget = Some(bytes);
    }

    /// Reports the remaining test write allowance, or None when writes are unrestricted.
    #[cfg(test)]
    pub(crate) fn write_budget(&self) -> Option<usize> {
        self.write_budget
    }

    /// Releases write pressure and notifies the most recent registered writer.
    #[cfg(test)]
    pub(crate) fn resume_writes(&mut self) {
        self.write_budget = None;
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for UpgradeIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(remaining) = this.remaining else {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        };
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if remaining == 0 {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        // A small initialized scratch buffer keeps the bound safe without unsafe ReadBuf bookkeeping.
        let mut scratch = [0; 4096];
        let count = remaining.min(buf.remaining()).min(scratch.len());
        let mut read = ReadBuf::new(&mut scratch[..count]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                this.remaining = Some(remaining - read.filled().len());
                buf.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for UpgradeIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        #[cfg(test)]
        {
            let bytes = if let Some(remaining) = this.write_budget {
                if remaining == 0 && !bytes.is_empty() {
                    this.write_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                &bytes[..bytes.len().min(remaining)]
            } else {
                bytes
            };
            let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
            if let (Some(remaining), Poll::Ready(Ok(count))) = (&mut this.write_budget, &result) {
                *remaining -= *count;
            }
            result
        }
        #[cfg(not(test))]
        {
            Pin::new(&mut this.inner).poll_write(cx, bytes)
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Builds verified TLS with the same explicit provider and public roots for both edges.
pub(crate) fn connector() -> Result<Connector, tokio_rustls::rustls::Error> {
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
        .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config).into()))
}
