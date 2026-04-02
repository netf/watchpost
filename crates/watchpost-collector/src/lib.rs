pub mod ancestry;
pub mod context;
pub mod grpc;
pub mod manifest;
pub mod proto;

/// Generated Tetragon protobuf types.
pub mod tetragon {
    tonic::include_proto!("tetragon");
}
