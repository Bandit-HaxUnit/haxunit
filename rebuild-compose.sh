#!/bin/bash

if ! command -v docker-compose &> /dev/null
then
    echo "[HaxUnit] Docker Compose is not installed. Installing Docker Compose..."

    # Install Docker Compose (assuming Linux environment with sudo)
    sudo curl -L "https://github.com/docker/compose/releases/download/v2.11.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose

    # Verify installation
    if command -v docker-compose &> /dev/null
    then
        echo "[HaxUnit] Docker Compose installed successfully."
    else
        echo "[HaxUnit] Failed to install Docker Compose. Exiting."
        exit 1
    fi
fi

echo "[HaxUnit] Running docker-compose down"
docker-compose down --volumes --remove-orphans

echo "[HaxUnit] Running docker-compose build"
docker-compose build || { echo "[HaxUnit] Failed to build. Exiting."; exit 1; }

echo "[HaxUnit] docker-compose up -d"
docker-compose up -d || { echo "[HaxUnit] Failed to start containers. Exiting."; exit 1; }

if docker ps | grep -q haxunit; then
  clear
  echo "🎉 Installation Complete! 🎉"
  echo "HaxUnit is now ready to rock!"
  echo "Time to find those vulnerabilities and patch them like a pro! 🕵️‍♂️🔍"
  echo ""
  echo "🚀 To start scanning, run the following command:"
  echo "haxunit -d <domain>"
  docker exec -it haxunit /bin/bash
else
  echo "[HaxUnit] haxunit container is not running - check errors above."
fi