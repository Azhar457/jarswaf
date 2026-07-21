#!/bin/bash
set -e

echo "Building test image..."
podman build -t jarswaf-test-image -f Dockerfile.test .

echo "Starting jarswaf-agent container with BPF privileges..."
podman rm -f jarswaf-ebpf-test || true
podman run -d --name jarswaf-ebpf-test \
  --privileged \
  --ulimit memlock=-1:-1 \
  -p 8080:8080 \
  -v $(pwd)/jarswaf-ebpf/target/bpfel-unknown-none/release/jarswaf-ebpf:/app/jarswaf-ebpf \
  -v $(pwd)/target/release/jarswaf:/app/jarswaf \
  -v $(pwd)/test_ebpf_config.toml:/app/config.toml \
  jarswaf-test-image \
  /app/jarswaf --config /app/config.toml agent

# Give it 3 seconds to start
sleep 3

# Check if container is running
if ! podman ps | grep jarswaf-ebpf-test > /dev/null; then
    echo "Container failed to start. Logs:"
    podman logs jarswaf-ebpf-test
    exit 1
fi

echo "======================================"
echo "Connection test BEFORE block (should succeed with 502 Bad Gateway since no upstream)..."
curl -s -v "http://127.0.0.1:8080/" 2>&1 | grep "HTTP/" || true
echo "======================================"

echo "Triggering SQLi attack to ban the slirp4netns gateway IP..."
for i in {1..5}; do
  curl -s -o /dev/null "http://127.0.0.1:8080/?q=1'%20OR%20'1'='1" || true
done

echo "Waiting 2 seconds for XDP block..."
sleep 2

echo "======================================"
echo "Connection test AFTER block (Expected to fail/timeout)..."
if curl -s -v --max-time 3 "http://127.0.0.1:8080/" 2>&1 | grep "HTTP/"; then
    echo "FAILURE: curl succeeded. XDP did NOT block the IP."
    podman logs jarswaf-ebpf-test
    exit 1
else
    echo "SUCCESS: curl timed out! XDP successfully dropped the packets in the kernel."
fi
echo "======================================"
