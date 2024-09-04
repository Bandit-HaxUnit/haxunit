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