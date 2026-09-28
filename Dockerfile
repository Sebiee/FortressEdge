FROM golang:1.27-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        make \
        ca-certificates \
        iproute2 \
        qemu-system-x86 \
        e2fsprogs \
        gzip \
        curl \
        python3 \
        isolinux \
        syslinux-common \
    && rm -rf /var/lib/apt/lists/*

# compose bind-mounts /src as the host user; go build stamps VCS as root.
RUN git config --system --add safe.directory /src

WORKDIR /src
ENV CGO_ENABLED=0
