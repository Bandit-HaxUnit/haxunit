python3 main.py --install
source $HOME/.cargo/env
rustup update
cargo install ripgen

echo "[HaxUnit] Succesfully installed - you can start scanning now."
echo "[HaxUnit] Example: python3 main.py -d example.com"