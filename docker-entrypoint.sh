#!/bin/bash
set -euo pipefail

# Function to read a secret from the file system
read_secret() {
  # Usage: read_secret "secret_name"
  local secret_path="/run/secrets/$1"
  if [[ -f "$secret_path" ]]; then
    cat "$secret_path"
  fi
}

# Export secrets as environment variables for legacy applications if needed.
# The most secure method is to modify the app to read from /run/secrets directly.
export WPSCAN_API_KEY=$(read_secret "wpscan_api_key")
export ACUNETIX_API_KEY=$(read_secret "acunetix_api_key")
export NUCLEI_API_KEY=$(read_secret "nuclei_api_key")

# Start OpenVPN in the background if the configuration file is provided.
if [[ -n "$HTB_OPENVPN_FILE" && -f "$HTB_OPENVPN_FILE" ]]; then
    echo "Starting OpenVPN connection in the background..."
    # Ensure the command is run in a way that doesn't block the entrypoint
    tmux new-session -d "openvpn --config ${HTB_OPENVPN_FILE}"
else
    echo "VPN not started. HTB_OPENVPN_FILE is not set or file not found."
fi

# Execute the command passed to the container (e.g., ["tail", "-f", "/dev/null"])
exec "$@"