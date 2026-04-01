fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_files = &[
        "../../proto/tetragon/sensors.proto",
        "../../proto/tetragon/events.proto",
        "../../proto/tetragon/tetragon.proto",
        "../../proto/tetragon/capabilities.proto",
        "../../proto/tetragon/stack.proto",
        "../../proto/tetragon/bpf.proto",
    ];

    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(proto_files, &["../../proto"])?;

    Ok(())
}
