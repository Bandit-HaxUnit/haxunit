#
# ===== Builder Stage =====
#
# Using a specific, version-pinned Alpine image for a minimal and secure build environment.
# Alpine is significantly smaller than the default Debian-based images.
FROM golang:1.24.4-alpine AS builder

# Set build-time arguments.
ARG NUCLEI_API_KEY

# Install only essential build-time dependencies.
# Using --no-cache reduces image size. git is needed for 'go install'.
RUN apk add --no-cache git

# Set up Go environment for the builder.
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

# Create a non-root user for the build process itself. This is an advanced
# security practice to avoid running even the build commands as root.
RUN addgroup -S builder && adduser -S -G builder builder
USER builder
WORKDIR /home/builder

# --- Go Tooling Installation ---
# First, copy only the necessary files to download dependencies.
# This layer is only re-built if the list of tools changes.
COPY --chown=builder:builder go.mod go.sum ./
RUN go mod download

# Now, install the tools. This leverages the downloaded dependencies.
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN /home/builder/go/bin/pdtm -ia -bp /home/builder/go/bin
RUN go install -v github.com/tomnomnom/unfurl@latest
RUN go install -v github.com/ffuf/ffuf/v2@latest

# Update Nuclei templates and authenticate if the API key is provided.
# This runs as the non-root builder user.
RUN /home/builder/go/bin/nuclei -update-templates
RUN if [ -n "$NUCLEI_API_KEY" ]; then \
        echo "$NUCLEI_API_KEY" | /home/builder/go/bin/nuclei -auth; \
    else \
        echo "NUCLEI_API_KEY is not set, skipping Nuclei authentication."; \
    fi

#
# ===== Final Stage =====
#
# Start from a minimal, non-root base image. python:3.12-slim is a good choice.
FROM python:3.12-slim

# Set environment variables for Python.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a non-root user and group for the final application.
# The user is named 'haxunit' for clarity.
RUN addgroup --system haxunit && adduser --system --ingroup haxunit haxunit

# Install only essential runtime dependencies.
# We are NOT installing docker.io. The container should use the host's Docker socket if needed.
# --no-install-recommends prevents installation of unnecessary packages.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        expect \
        sudo \
        cewl \
        vim \
        dos2unix \
        tmux \
        openvpn \
        libpcap-dev && \
    # Clean up APT cache to reduce image size.
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory and ensure it's owned by our non-root user.
WORKDIR /app
RUN chown haxunit:haxunit /app

# Switch to the non-root user for all subsequent operations.
USER haxunit

# --- Python Dependencies ---
# Copy and install Python requirements first to leverage caching.
# This layer is only invalidated if requirements.txt changes.
COPY --chown=haxunit:haxunit requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt
ENV PATH="/home/haxunit/.local/bin:${PATH}"

# --- Application and Tooling Setup ---
# Copy the compiled Go tools and Nuclei configuration from the builder stage.
# Ensure correct ownership is set.
COPY --from=builder --chown=haxunit:haxunit /home/builder/go/bin/ /home/haxunit/.local/bin/
COPY --from=builder --chown=haxunit:haxunit /home/builder/.config/nuclei/ /home/haxunit/.config/nuclei/

# Copy the rest of the application code.
# This is one of the last steps, as code changes most frequently.
COPY --chown=haxunit:haxunit . .

# Convert main.py to Unix format and make it executable.
RUN dos2unix /app/main.py && \
    chmod +x /app/main.py

# Create a symlink in a user-owned bin directory for easy execution.
RUN ln -s /app/main.py /home/haxunit/.local/bin/haxunit

# Create a directory for OpenVPN configuration.
RUN mkdir -p /etc/openvpn/

# The CMD is simplified. The HTB_OPENVPN_FILE logic should be handled by an
# entrypoint script or the orchestration layer (e.g., Docker Compose).
CMD ["tail", "-f", "/dev/null"]