# Use an official Python base image
FROM python:3.8

# Switch default shell to bash
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Install necessary packages and tools
RUN apt-get update && \
    apt-get install -y \
        expect \
        sudo \
        cargo \
        docker.io \
        wget \
        tar \
        libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Go
ENV GO_VERSION=1.22.5
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

# Set up Go environment
ENV PATH="/usr/local/go/bin:/root/go/bin:$PATH"
ENV GOPATH="/root/go"
ENV GOBIN="/root/go/bin"

# Install Rust using rustup and set up the environment
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.65.0 -y && \
    export PATH="/root/.cargo/bin:${PATH}" && \
    cargo install ripgen

# Set up Cargo PATH
ENV PATH="$PATH:$HOME/.cargo/bin"

# Install tools
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/tomnomnom/unfurl@latest
RUN go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# TO-DO: Implement pdtm to install tools
# go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest

# Update nuclei templates
RUN nuclei -update-templates

# Set environment variable for API key
ARG NUCLEI_API_KEY
ENV NUCLEI_API_KEY=${NUCLEI_API_KEY}

# Conditionally run expect if NUCLEI_API_KEY is set
RUN if [ -n "$NUCLEI_API_KEY" ]; then \
        expect -c ' \
            spawn nuclei -auth; \
            expect "Enter PDCP API Key (exit to abort):"; \
            send "$env(NUCLEI_API_KEY)\r"; \
            expect eof; \
        '; \
    else \
        echo "NUCLEI_API_KEY is not set, skipping nuclei authentication"; \
    fi

# Set the working directory
WORKDIR /app

# Copy Python dependencies and install them
COPY requirements.txt requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .