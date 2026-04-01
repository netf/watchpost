//! Tetragon gRPC client for connecting to the Tetragon daemon.

use anyhow::{Context, Result};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use crate::tetragon::{
    fine_guidance_sensors_client::FineGuidanceSensorsClient, GetEventsRequest,
    GetEventsResponse, GetHealthStatusRequest, HealthStatusType,
};

/// A wrapper around the generated Tetragon gRPC client that handles
/// connection management for both Unix socket and TCP endpoints.
#[derive(Debug, Clone)]
pub struct TetragonClient {
    inner: FineGuidanceSensorsClient<Channel>,
}

impl TetragonClient {
    /// Connect to a Tetragon endpoint.
    ///
    /// Supported endpoint formats:
    /// - `unix:///var/run/tetragon/tetragon.sock` — Unix domain socket
    /// - `http://host:port` or `https://host:port` — TCP connection
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let channel = if let Some(socket_path) = endpoint.strip_prefix("unix://") {
            let socket_path = socket_path.to_owned();
            // For Unix sockets, the URI in Endpoint is a dummy — the actual
            // connection is established by the connector closure.
            Endpoint::try_from("http://[::]:50051")
                .context("failed to create endpoint")?
                .connect_with_connector(service_fn(move |_: Uri| {
                    let path = socket_path.clone();
                    async move {
                        UnixStream::connect(path)
                            .await
                            .map(hyper_util::rt::TokioIo::new)
                    }
                }))
                .await
                .context("failed to connect to Tetragon Unix socket")?
        } else {
            // TCP endpoint — connect directly.
            Endpoint::try_from(endpoint.to_owned())
                .context("invalid endpoint URI")?
                .connect()
                .await
                .context("failed to connect to Tetragon TCP endpoint")?
        };

        let inner = FineGuidanceSensorsClient::new(channel);
        Ok(Self { inner })
    }

    /// Open a server-streaming event stream from Tetragon.
    ///
    /// Returns a `tonic::Streaming` that yields `GetEventsResponse` messages.
    pub async fn event_stream(
        &mut self,
    ) -> Result<tonic::Streaming<GetEventsResponse>> {
        let request = GetEventsRequest {
            allow_list: vec![],
            deny_list: vec![],
            aggregation_options: None,
            field_filters: vec![],
        };

        let response = self
            .inner
            .get_events(request)
            .await
            .context("GetEvents RPC failed")?;

        Ok(response.into_inner())
    }

    /// Call the GetHealth RPC to verify that the Tetragon daemon is running.
    pub async fn health(&mut self) -> Result<()> {
        let request = GetHealthStatusRequest {
            event_set: vec![HealthStatusType::Status as i32],
        };

        let response = self
            .inner
            .get_health(request)
            .await
            .context("GetHealth RPC failed")?;

        let statuses = &response.into_inner().health_status;
        tracing::debug!(count = statuses.len(), "Tetragon health check passed");
        Ok(())
    }

    /// Returns a mutable reference to the underlying generated gRPC client.
    pub fn inner_mut(&mut self) -> &mut FineGuidanceSensorsClient<Channel> {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires a running Tetragon instance
    async fn integration_connect_and_health() {
        let mut client = TetragonClient::connect("unix:///var/run/tetragon/tetragon.sock")
            .await
            .expect("failed to connect");

        client.health().await.expect("health check failed");
    }

    #[tokio::test]
    #[ignore] // Requires a running Tetragon instance
    async fn integration_event_stream() {
        use futures::StreamExt;

        let mut client = TetragonClient::connect("unix:///var/run/tetragon/tetragon.sock")
            .await
            .expect("failed to connect");

        let mut stream = client.event_stream().await.expect("failed to open stream");

        // Read at least one event (Tetragon should always be emitting exec events).
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
            .await
            .expect("timed out waiting for event")
            .expect("stream ended unexpectedly")
            .expect("gRPC error");

        assert!(msg.event.is_some(), "expected a non-empty event");
    }
}
