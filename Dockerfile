# Stage 1: Builder - Installs all tools and build dependencies
FROM kalilinux/kali-rolling AS builder

WORKDIR /build
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and tools in a single layer with cleanup
RUN apt-get update && apt-get install -y --no-install-recommends \
  git \
  build-essential \
  libpcap-dev \
  python3 \
  python3-pip \
  python3-setuptools \
  nmap \
  ruby \
  ruby-dev \
  perl \
  dnsenum \
  whatweb \
  golang-go \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install masscan from source and clean up in same layer
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan.git && \
  cd masscan && \
  make -j$(nproc) && \
  mv bin/masscan /usr/local/bin/masscan && \
  cd .. && \
  rm -rf masscan

# Set up Go environment and install Go-based tools with caching optimization
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  go install -v github.com/owasp-amass/amass/v4/...@v4.2.0 && \
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.5 && \
  go install github.com/OJ/gobuster/v3@v3.6.0

# Install Python-based tools with cache and cleanup
RUN git clone --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester && \
  cd /opt/theHarvester && \
  pip3 install --no-cache-dir --break-system-packages . && \
  git clone --depth 1 https://github.com/lanmaster53/recon-ng.git /opt/recon-ng && \
  cd /opt/recon-ng && \
  pip3 install --no-cache-dir --break-system-packages -r REQUIREMENTS && \
  git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch && \
  rm -rf /root/.cache/pip

# Stage 2: Final Image - Minimal runtime
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install only essential runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
  nmap \
  ruby \
  perl \
  dnsenum \
  whatweb \
  libnet-dns-perl \
  libnet-ip-perl \
  libnet-whois-ip-perl \
  libwww-perl \
  libpq-dev \
  python3 \
  python3-pip \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy only necessary binaries and tools
COPY --from=builder /usr/local/bin/masscan /usr/local/bin/
COPY --from=builder /go/bin/amass /usr/local/bin/
COPY --from=builder /go/bin/subfinder /usr/local/bin/
COPY --from=builder /go/bin/gobuster /usr/local/bin/
COPY --from=builder /opt/theHarvester /opt/theharvester
COPY --from=builder /opt/recon-ng /opt/recon-ng
COPY --from=builder /opt/dirsearch /opt/dirsearch

WORKDIR /app

# Copy application files and install dependencies
COPY . .
RUN pip3 install --no-cache-dir --break-system-packages /opt/theharvester && \
  pip3 install --no-cache-dir --break-system-packages -r /opt/dirsearch/requirements.txt && \
  pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
  rm -rf /root/.cache/pip

# Create symlinks for tools
RUN ln -s /opt/theharvester/theHarvester.py /usr/local/bin/theharvester && \
  ln -s /opt/recon-ng/recon-ng /usr/local/bin/recon-ng && \
  ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

EXPOSE 8080

CMD ["python3", "main.py"]