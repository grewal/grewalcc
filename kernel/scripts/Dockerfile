FROM docker.io/library/debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    lsb-release gnupg curl wget ca-certificates jq bc bison flex \
    libelf-dev libssl-dev dwarves libdw-dev git make kmod cpio binutils \
    python3 time dpkg-dev debhelper rsync lz4 zstd xz-utils \
    initramfs-tools xxd gawk \
    && apt-get clean
# dwarves provides pahole >= 1.16 (Trixie ships 1.25), which is required for
# CONFIG_DEBUG_INFO_BTF=y to produce a real BTF section in vmlinux.
# Without pahole the BTF build step silently produces an empty section and
# CO-RE BPF programs break at runtime with "no BTF found".
# LLVM 21 pinned
RUN curl -sSL https://apt.llvm.org/llvm.sh | bash -s -- 21 all
RUN apt-get update && apt-get install -y \
    clang-21 lld-21 llvm-21 llvm-21-dev libclang-21-dev \
    && apt-get clean

# Stable symlinks — krun() uses absolute paths but these help ad-hoc work
RUN ln -sf /usr/bin/clang-21        /usr/bin/clang       && \
    ln -sf /usr/bin/ld.lld-21       /usr/bin/ld.lld      && \
    ln -sf /usr/bin/llvm-objcopy-21 /usr/bin/llvm-objcopy && \
    ln -sf /usr/bin/llvm-readelf-21 /usr/bin/llvm-readelf && \
    ln -sf /usr/bin/llvm-strip-21   /usr/bin/llvm-strip  && \
    ln -sf /usr/bin/llvm-ar-21      /usr/bin/llvm-ar     && \
    ln -sf /usr/bin/llvm-nm-21      /usr/bin/llvm-nm

# Google Cloud SDK
RUN curl -sSL https://sdk.cloud.google.com | bash -s -- --disable-prompts
ENV PATH=/root/google-cloud-sdk/bin:$PATH

WORKDIR /root
ENTRYPOINT ["python3", "/upgrade_kernel.py"]
