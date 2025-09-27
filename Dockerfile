# Stage 1: Builder - Installs all tools and build dependencies
FROM kalilinux/kali-rolling AS builder

WORKDIR /build
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and tools in a single layer
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
  && rm -rf /var/lib/apt/lists/*

# Install masscan from source
RUN git clone https://github.com/robertdavidgraham/masscan.git && \
  cd masscan && \
  make -j4 && \
  mv bin/masscan /usr/local/bin/masscan && \
  cd .. && \
  rm -rf masscan

# Set up Go environment and install Go-based tools with pinned versions for caching
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN go install -v github.com/owasp-amass/amass/v4/...@v4.2.0 && \
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.5 && \
  go install github.com/OJ/gobuster/v3@v3.6.0

# Install Python-based tools
RUN git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && \
  cd /opt/theHarvester && \
  pip3 install . --break-system-packages && \
  git clone https://github.com/lanmaster53/recon-ng.git /opt/recon-ng && \
  cd /opt/recon-ng && \
  pip3 install -r REQUIREMENTS --break-system-packages && \
  git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch

# Stage 2: Final Image - A smaller image with only necessary tools and runtime
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies AND libcap2-bin for setcap
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
  python3-setuptools \
  && rm -rf /var/lib/apt/lists/*


COPY --from=builder /usr/local/bin/masscan /usr/local/bin/
COPY --from=builder /go/bin/amass /usr/local/bin/
COPY --from=builder /go/bin/subfinder /usr/local/bin/
COPY --from=builder /go/bin/gobuster /usr/local/bin/
COPY --from=builder /opt/theHarvester /opt/theHarvester
COPY --from=builder /opt/recon-ng /opt/recon-ng
COPY --from=builder /opt/dirsearch /opt/dirsearch

WORKDIR /app

COPY . .

RUN pip3 install /opt/theHarvester --break-system-packages && \
  pip3 install -r /opt/dirsearch/requirements.txt --break-system-packages

# Install Python application dependencies
RUN pip3 install --no-cache-dir --user -r requirements.txt --break-system-packages

RUN ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theharvester && \
  ln -s /opt/recon-ng/recon-ng /usr/local/bin/recon-ng && \
  ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

EXPOSE 8080

CMD ["python3", "main.py"]
