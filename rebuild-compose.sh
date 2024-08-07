echo "[HaxUnit] Running docker-compose down"
docker-compose down || true

echo "[HaxUnit] Running docker-compose build"
docker-compose build || true

echo "[HaxUnit] docker-compose up -d"
docker-compose up -d || true

clear
echo "🎉 Installation Complete! 🎉"
echo "HaxUnit is now ready to rock!"
echo "Time to find those vulnerabilities and patch them like a pro! 🕵️‍♂️🔍"
echo ""
echo "🚀 To start scanning, run the following command:"
echo "python3 main.py -d <domain>"
docker exec -it haxunit /bin/bash