#!/usr/bin/env bash
set -euo pipefail

# Chạy Memgraph Platform gồm Memgraph database, MAGE và Memgraph Lab UI.
# Sau khi container chạy, mở http://localhost:3000 để vào Memgraph Lab.
docker run -d \
  --name memgraph-platform \
  -p 7687:7687 \
  -p 7444:7444 \
  -p 3000:3000 \
  -v mg_lib:/var/lib/memgraph \
  -v mg_log:/var/log/memgraph \
  -v mg_etc:/etc/memgraph \
  memgraph/memgraph-platform:latest

echo "Memgraph Lab: http://localhost:3000"
echo "Bolt URI: bolt://localhost:7687"
