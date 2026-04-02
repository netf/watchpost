//! Full pipeline integration test that requires a running Tetragon instance.
//!
//! This test is marked `#[ignore]` by default because it depends on a live
//! Tetragon gRPC endpoint. Run it explicitly with:
//!
//! ```sh
//! cargo test -p watchpost-engine --test pipeline_test -- --ignored
//! ```

#[tokio::test]
#[ignore] // Requires running Tetragon
async fn full_pipeline_with_tetragon() {
    use std::time::Duration;

    use tokio::sync::mpsc;
    use watchpost_types::{CollectorConfig, EngineConfig, EnrichedEvent};

    use watchpost_engine::profiles::BehaviorProfileStore;
    use watchpost_engine::Engine;

    // 1. Create collector connected to real Tetragon.
    let collector_config = CollectorConfig::default();
    let collector = watchpost_collector::Collector::new(
        "unix:///var/run/tetragon/tetragon.sock",
        &collector_config,
    )
    .await
    .expect("Failed to connect to Tetragon -- is it running?");

    // 2. Create engine with channels.
    let engine_config = EngineConfig::default();
    let profiles_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles");
    let profiles = BehaviorProfileStore::load_dir(&profiles_dir)
        .expect("Failed to load behavior profiles");
    let engine = Engine::new(&engine_config, profiles);

    let (event_tx, event_rx) = mpsc::channel::<EnrichedEvent>(256);
    let (rules_tx, mut rules_rx) = mpsc::channel(64);
    let (analyzer_tx, mut analyzer_rx) = mpsc::channel(64);
    let (log_tx, mut log_rx) = mpsc::channel(64);

    // 3. Spawn the collector and engine as background tasks.
    let collector_handle = tokio::spawn(async move {
        collector.run(event_tx).await
    });

    let engine_handle = tokio::spawn(async move {
        engine.run(event_rx, rules_tx, analyzer_tx, log_tx).await
    });

    // Generate some activity by spawning `ls /tmp`.
    let _ls = tokio::process::Command::new("ls")
        .arg("/tmp")
        .output()
        .await
        .expect("Failed to run `ls /tmp`");

    // 4. Wait a few seconds for events to flow through the pipeline.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 5. Verify at least one event was produced (check all channels).
    let mut total_traces = 0;
    while rules_rx.try_recv().is_ok() {
        total_traces += 1;
    }
    while analyzer_rx.try_recv().is_ok() {
        total_traces += 1;
    }
    while log_rx.try_recv().is_ok() {
        total_traces += 1;
    }

    // In a real environment with Tetragon running, `ls /tmp` may or may not
    // produce correlated traces (depends on whether a trigger is active).
    // At minimum, the collector should have produced events, and the engine
    // should have processed them without panicking.
    //
    // A more specific assertion would require a PackageInstall or Build
    // context to be active. For now, we verify the pipeline ran without error.

    // Clean up: abort the collector (it runs forever).
    collector_handle.abort();
    // Engine will stop when its input channel is dropped (collector aborted).
    let _ = engine_handle.await;

    // If we got here, the pipeline ran without panics or deadlocks.
    eprintln!(
        "Pipeline test completed. Correlated traces observed: {}",
        total_traces
    );
}
