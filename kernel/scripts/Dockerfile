FROM docker.io/library/debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install System Foundations + OpenSSH Client
# OpenSSH is strictly required by gcloud to build IAP tunnels.
RUN apt-get update && apt-get install -y \
    lsb-release gnupg curl wget ca-certificates jq bc bison flex \
    libelf-dev libssl-dev dwarves libdw-dev git make kmod cpio binutils \
    python3 python3-pip python3-crcmod time dpkg-dev debhelper rsync \
    lz4 zstd xz-utils initramfs-tools xxd gawk \
    openssh-client \
    && apt-get clean

# 2. Install Google Cloud CLI via Official Repository
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" \
    | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && apt-get install -y google-cloud-cli && \
    apt-get clean

# 3. LLVM 21 Pinned Toolchain
RUN curl -sSL https://apt.llvm.org/llvm.sh | bash -s -- 21 all
RUN apt-get update && apt-get install -y \
    clang-21 lld-21 llvm-21 llvm-21-dev libclang-21-dev \
    && apt-get clean

# 4. Stable LLVM Symlinks
RUN ln -sf /usr/bin/clang-21        /usr/bin/clang        && \
    ln -sf /usr/bin/ld.lld-21       /usr/bin/ld.lld       && \
    ln -sf /usr/bin/llvm-objcopy-21 /usr/bin/llvm-objcopy && \
    ln -sf /usr/bin/llvm-readelf-21 /usr/bin/llvm-readelf && \
    ln -sf /usr/bin/llvm-strip-21   /usr/bin/llvm-strip   && \
    ln -sf /usr/bin/llvm-ar-21      /usr/bin/llvm-ar      && \
    ln -sf /usr/bin/llvm-nm-21      /usr/bin/llvm-nm

# NOTE: Do NOT set core/ssh_command.
# gcloud manages SSH internally for IAP tunnel support. Overriding it
# with the system 'ssh' binary breaks gcloud compute scp/ssh via IAP.

WORKDIR /root
ENTRYPOINT ["python3", "/upgrade_kernel.py"]
