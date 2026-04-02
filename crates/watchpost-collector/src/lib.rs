pub mod ancestry;
pub mod context;
pub mod grpc;
pub mod manifest;
pub mod proto;

/// Generated Tetragon protobuf types.
pub mod tetragon {
    tonic::include_proto!("tetragon");
}

use anyhow::{Context, Result};
use futures::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use watchpost_types::{CollectorConfig, EnrichedEvent, EventKind};

use crate::ancestry::ProcessAncestryBuilder;
use crate::context::ActionContextInferrer;
use crate::grpc::TetragonClient;
use crate::manifest::PackageManifestCache;

/// The main collector that wires together the gRPC client, process ancestry
/// builder, action context inferrer, and package manifest cache into a single
/// event-processing pipeline.
pub struct Collector {
    client: TetragonClient,
    ancestry: ProcessAncestryBuilder,
    #[allow(dead_code)] // kept for documentation: the collector uses context inference
    context_inferrer: ActionContextInferrer,
    manifest_cache: PackageManifestCache,
    max_ancestry_depth: usize,
}

impl Collector {
    /// Create a new `Collector` by connecting to the Tetragon gRPC endpoint
    /// and initializing all sub-components from the provided configuration.
    pub async fn new(
        tetragon_endpoint: &str,
        collector_config: &CollectorConfig,
    ) -> Result<Self> {
        let client = TetragonClient::connect(tetragon_endpoint)
            .await
            .context("failed to connect to Tetragon")?;

        let ancestry = ProcessAncestryBuilder::new();
        let context_inferrer = ActionContextInferrer;
        let manifest_cache = PackageManifestCache::new(collector_config.manifest_cache_size);
        let max_ancestry_depth = collector_config.max_ancestry_depth;

        debug!(
            endpoint = tetragon_endpoint,
            max_ancestry_depth,
            manifest_cache_size = collector_config.manifest_cache_size,
            "Collector initialized"
        );

        Ok(Self {
            client,
            ancestry,
            context_inferrer,
            manifest_cache,
            max_ancestry_depth,
        })
    }

    /// Run the main event loop, consuming events from the Tetragon gRPC stream,
    /// enriching them with ancestry and context, and sending them on `tx`.
    ///
    /// This method takes ownership of `self` and runs until the stream ends
    /// or an unrecoverable error occurs.
    pub async fn run(mut self, tx: mpsc::Sender<EnrichedEvent>) -> Result<()> {
        let mut stream = self
            .client
            .event_stream()
            .await
            .context("failed to open Tetragon event stream")?;

        debug!("Collector event loop started");

        while let Some(result) = stream.next().await {
            let response = match result {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(error = %e, "gRPC stream error, skipping message");
                    continue;
                }
            };

            // Convert proto response to domain event; skip unhandled types.
            let event = match proto::convert_response(&response) {
                Ok(Some(ev)) => ev,
                Ok(None) => continue,
                Err(e) => {
                    warn!(error = %e, "failed to convert proto event, skipping");
                    continue;
                }
            };

            let pid = event.process_id;
            let is_exit = matches!(event.kind, EventKind::ProcessExit { .. });

            // Build ancestry chain for the process.
            let ancestry = self.ancestry.build(pid, self.max_ancestry_depth);

            // Infer action context from ancestry.
            let context = ActionContextInferrer::infer(&ancestry);

            let enriched = EnrichedEvent {
                event,
                ancestry,
                context,
            };

            // Send enriched event; don't block if the channel is full.
            match tx.try_send(enriched) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        pid,
                        "event channel full, dropping enriched event"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!("event channel closed, stopping collector");
                    return Ok(());
                }
            }

            // Evict process from ancestry cache on exit events.
            if is_exit {
                self.ancestry.evict(pid);
            }
        }

        debug!("Tetragon event stream ended");
        Ok(())
    }

    /// Check the health of the Tetragon daemon via the gRPC health endpoint.
    pub async fn health_check(&mut self) -> Result<()> {
        self.client.health().await
    }

    /// Returns a reference to the manifest cache (useful for external enrichment).
    pub fn manifest_cache(&self) -> &PackageManifestCache {
        &self.manifest_cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use watchpost_types::CollectorConfig;

    #[tokio::test]
    async fn test_collector_new_fails_without_tetragon() {
        let config = CollectorConfig::default();
        // Use a bogus endpoint that cannot be connected to.
        let result = Collector::new("http://127.0.0.1:1", &config).await;
        assert!(
            result.is_err(),
            "Collector::new should fail when Tetragon is unreachable"
        );
    }
}
