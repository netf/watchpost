pub mod grpc;
pub mod proto;

/// Generated Tetragon protobuf types.
pub mod tetragon {
    tonic::include_proto!("tetragon");
}
