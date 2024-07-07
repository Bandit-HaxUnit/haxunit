CONTAINERNAME="haxunit"
IMAGE="haxunit_image"

echo "[HaxUnit] Stopping container $CONTAINERNAME"
docker stop $CONTAINERNAME || true

echo "[HaxUnit] Removing container $CONTAINERNAME"
docker rm $CONTAINERNAME || true

echo "[HaxUnit] Removing image $IMAGE"
docker rmi $IMAGE || true

echo "[HaxUnit] Building image $IMAGE"
docker build --tag $IMAGE . || exit 1

echo "[HaxUnit] Running container $CONTAINERNAME"
docker run -d -t -v /var/run/docker.sock:/var/run/docker.sock --name $CONTAINERNAME $IMAGE || exit 1

echo "[HaxUnit] Started installation process"
docker exec -it $CONTAINERNAME /bin/bash -c "python3 main.py --install"

clear
echo "[HaxUnit] Installation complete - you can start scanning now."
docker exec -it $CONTAINERNAME /bin/bash