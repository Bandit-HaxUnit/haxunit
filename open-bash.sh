#!/bin/bash

if docker ps | grep -q haxunit; then
  echo "[HaxUnit] Entering the HaxUnit container"
  docker exec -it haxunit /bin/bash
else
  echo "[HaxUnit] HaxUnit container is not running. Please start it first using ./rebuild-compose.sh"
fi