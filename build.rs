fn main() {
    // Ensure protoc is available via vendored binary
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());

    // Compile the gRPC proto file
    tonic_build::compile_protos("proto/waf_sync.proto")
        .unwrap_or_else(|e| panic!("Failed to compile protos: {}", e));
}
