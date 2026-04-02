pub mod agent_loop;
pub mod backend;
pub mod client;
pub mod context_builder;
pub mod gate;
pub mod ollama;
pub mod rate_limiter;
pub mod skill;
pub mod tools;

use anyhow::Result;
use tracing::{info, warn};

use watchpost_types::{CorrelatedTrace, Verdict};

use crate::agent_loop::AgentLoop;
use crate::backend::LlmBackend;
use crate::rate_limiter::RateLimiter;
use crate::skill::SkillSpec;

// ---------------------------------------------------------------------------
// Top-level Analyzer
// ---------------------------------------------------------------------------

/// The top-level analyzer that combines the agent loop, rate limiter, and
/// queue processing into a single run loop.
pub struct Analyzer {
    agent_loop: AgentLoop,
    rate_limiter: RateLimiter,
    #[allow(dead_code)]
    queue_size: usize,
}

impl Analyzer {
    pub fn new(
        client: Box<dyn LlmBackend>,
        skill: SkillSpec,
        max_tool_calls: u32,
        max_per_minute: u32,
        queue_size: usize,
    ) -> Self {
        Self {
            agent_loop: AgentLoop::new(client, skill, max_tool_calls),
            rate_limiter: RateLimiter::new(max_per_minute),
            queue_size,
        }
    }

    /// Run the analyzer loop, consuming traces from `rx` and sending verdicts
    /// on `verdict_tx`.
    ///
    /// Returns `Ok(())` when the input channel closes.
    pub async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<CorrelatedTrace>,
        verdict_tx: tokio::sync::mpsc::Sender<Verdict>,
    ) -> Result<()> {
        info!("analyzer run loop started");

        while let Some(trace) = rx.recv().await {
            let trace_id = trace.id;

            if !self.rate_limiter.try_acquire() {
                warn!(
                    trace_id = %trace_id,
                    "rate limit exceeded, skipping trace"
                );
                continue;
            }

            match self.agent_loop.analyze(&trace, None, None).await {
                Ok(verdict) => {
                    if verdict_tx.send(verdict).await.is_err() {
                        info!("verdict channel closed, shutting down analyzer");
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        trace_id = %trace_id,
                        error = %e,
                        "analysis failed for trace"
                    );
                }
            }
        }

        info!("analyzer run loop finished");
        Ok(())
    }
}
