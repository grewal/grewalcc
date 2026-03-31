#!/usr/bin/env python3

import subprocess, json, sys, os, base64, re
from urllib.request import urlopen

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTANCE = "gcc-gem-a"
ZONE     = "us-south1-a"
PROJECT  = "mysides"
USER     = "ygrewal"

LVER_SUFFIX = "-grewalcc"
LSM_LIST = "bpf,capability,landlock,lockdown,yama,integrity"

BOOT_ARGS = (
    "console=ttyS0,115200 "
    "earlyprintk=ttyS0,115200 "
    f"lsm={LSM_LIST} "
    "bpf_lsm.enabled=1 "
    "intel_pstate=disable "
    "mitigations=auto "
    "pcie_aspm=off "
    "selinux=0"
)

os.environ["LLVM"]     = "1"
os.environ["LLVM_IAS"] = "1"
os.environ["ARCH"]     = "x86_64"
os.environ["CC"]       = "clang-21"
os.environ["LD"]       = "ld.lld-21"

# ---------------------------------------------------------------------------
# Kernel config fragment
# ---------------------------------------------------------------------------
HARDENING_FRAGMENT = {
    "CONFIG_PREEMPT_DYNAMIC":                    "n",
    "CONFIG_PREEMPT_VOLUNTARY":                  "y",
    "CONFIG_CPU_MITIGATIONS":                    "n",
    "CONFIG_IKCONFIG":                           "y",
    "CONFIG_IKCONFIG_PROC":                      "y",
    "CONFIG_SECURITY":                           "y",
    "CONFIG_SECURITYFS":                         "y",
    "CONFIG_SECURITY_NETWORK":                   "y",
    "CONFIG_DEBUG_INFO_NONE":                    "n",
    "CONFIG_DEBUG_INFO":                         "y",
    "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT": "y",
    "CONFIG_DEBUG_INFO_BTF":                     "y",
    "CONFIG_OBJTOOL":                            "y",
    "CONFIG_FTRACE":                             "y",
    "CONFIG_FUNCTION_TRACER":                    "y",
    "CONFIG_DYNAMIC_FTRACE":                     "y",
    "CONFIG_FTRACE_MCOUNT_USE_OBJTOOL":          "y",
    "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS":   "y",
    "CONFIG_KALLSYMS_ALL":                       "y",
    "CONFIG_BPF":                                "y",
    "CONFIG_BPF_SYSCALL":                        "y",
    "CONFIG_BPF_JIT":                            "y",
    "CONFIG_BPF_JIT_ALWAYS_ON":                  "y",
    "CONFIG_PERF_EVENTS":                        "y",
    "CONFIG_BPF_EVENTS":                         "y",
    "CONFIG_BPF_LSM":                            "y",
    "CONFIG_CGROUP_BPF":                         "y",
    "CONFIG_GVE":                                "y",
    "CONFIG_LTO_CLANG_THIN":                     "y",
    "CONFIG_LRU_GEN":                            "y",
    "CONFIG_LRU_GEN_ENABLED":                    "y",
    "CONFIG_ZRAM":                               "y",
    "CONFIG_ZRAM_DEF_COMP_LZO":                  "y",
    "CONFIG_CPU_FREQ_GOV_PERFORMANCE":           "y",
    "CONFIG_DRM":                                "n",
    "CONFIG_AGP":                                "n",
}

REQUIRED_CONFIGS = [
    "CONFIG_SECURITYFS",
    "CONFIG_IKCONFIG",
    "CONFIG_IKCONFIG_PROC",
    "CONFIG_BPF_LSM",
    "CONFIG_PREEMPT_VOLUNTARY",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_LTO_CLANG_THIN",
    "CONFIG_GVE",
    "CONFIG_ZRAM",
]

OPTIONAL_CONFIGS = [
    "CONFIG_ZRAM_DEF_COMP_LZORLE",
    "CONFIG_BPF_LSM_PROGS_DEFAULT_ON",
]

def log_header(msg: str) -> None:
    print(f"\n{'='*80}\n{msg:^80}\n{'='*80}")

def run(cmd: str, capture: bool = False) -> str | None:
    result = subprocess.run(
        cmd, shell=True, check=True, executable="/bin/bash",
        capture_output=capture, text=True,
    )
    return result.stdout.strip() if capture else None

def build_grub_python(kver: str) -> str:
    safe_kver = kver.replace("\\", "\\\\").replace("'", "\\'")
    lines = [
        "import re, sys",
        "kver = '" + safe_kver + "'",
        "cfg = open('/boot/grub/grub.cfg').read()",
        "kp  = re.escape(kver)",
        "sub_pat = (r\"submenu\\s+(['\\\"])[^'\\\"]*Advanced options[^'\\\"]*\\1\" r\"\\s+\\$menuentry_id_option\\s+(['\\\"])([^'\\\"]+)\\2\")",
        "ent_pat = (r\"menuentry\\s+(['\\\"])[^'\\\"]*\" + kp + r\"[^'\\\"]*\\1\" r\"[^{]*\\$menuentry_id_option\\s+(['\\\"])([^'\\\"]+)\\2\")",
        "sub = re.search(sub_pat, cfg, re.DOTALL)",
        "ent = re.search(ent_pat, cfg, re.DOTALL)",
        "if sub and ent: print(sub.group(3) + '>' + ent.group(3)); sys.exit(0)",
        "if ent: print(ent.group(3)); sys.exit(0)",
        "print('FAILED'); sys.exit(1)",
    ]
    return "\n".join(lines) + "\n"

def build_deploy_script(kver: str, deb_name: str, boot_args: str) -> str:
    grub_py = build_grub_python(kver)
    return f"""\
#!/bin/bash
set -euo pipefail
KVER="{kver}"
DEB="{deb_name}"
BOOT_ARGS="{boot_args}"
STOCK_VMLINUZ=$(ls /boot/vmlinuz-6.* 2>/dev/null | grep -v grewalcc | head -1 || true)
if [[ -z "${{STOCK_VMLINUZ}}" ]]; then echo "FATAL: No safety-net."; exit 1; fi
find /boot -name "*grewalcc*" ! -name "*${{KVER}}*" -delete 2>/dev/null || true
apt-get purge -y linux-image-grewalcc 2>/dev/null || true
apt-get update -qq && apt-get install -y xxd gawk >/dev/null
dpkg -i "/tmp/${{DEB}}"
update-initramfs -c -k "${{KVER}}"
mkdir -p /etc/default/grub.d
echo "GRUB_CMDLINE_LINUX_DEFAULT=\\"${{BOOT_ARGS}}\\"" > /etc/default/grub.d/99-grewalcc.cfg
sed -i 's|^GRUB_DEFAULT=.*|GRUB_DEFAULT=saved|' /etc/default/grub
update-grub
cat > /tmp/grub_parse.py << 'PYEOF'
{grub_py}
PYEOF
GRUB_IDS=$(python3 /tmp/grub_parse.py)
grub-reboot "${{GRUB_IDS}}"
echo "[VM] Rebooting in 5s..."; sleep 5; reboot
"""

def main() -> None:
    log_header("PHASE 0: BEAST READINESS")
    run("clang-21 --version")
    run(f"gcloud compute instances describe {INSTANCE} --project {PROJECT} --zone {ZONE} --format='get(status)'")

    log_header("PHASE 1: SOURCE & CONFIGURATION")
    with urlopen("https://www.kernel.org/releases.json") as r:
        data = json.loads(r.read().decode())
    rel = next((rel for rel in data["releases"] if rel["moniker"] == "mainline"), None)
    ver, url = rel["version"], rel["source"]

    workspace = os.path.expanduser("~/kernel_orchestrator_build")
    os.makedirs(workspace, exist_ok=True)
    os.chdir(workspace)

    tar_path, src_path = f"linux-{ver}.tar.gz", f"linux-{ver}"
    if not os.path.exists(tar_path): run(f"wget -q -O {tar_path} {url}")

    # FIX: Create directory before tar extraction
    if not os.path.isdir(src_path):
        os.makedirs(src_path, exist_ok=True)
        run(f"tar -xf {tar_path} -C {src_path} --strip-components=1")

    os.chdir(src_path)
    run("make x86_64_defconfig")

    # Pass 1 & 2 logic
    for s in ["--enable CONFIG_IKCONFIG", "--enable CONFIG_IKCONFIG_PROC", "--enable CONFIG_SECURITYFS"]: run(f"./scripts/config {s}")
    run("make olddefconfig")

    with open("hardened.config", "w") as f:
        for k, v in HARDENING_FRAGMENT.items(): f.write(f"{k}={v}\n")
        f.write(f'CONFIG_LOCALVERSION="{LVER_SUFFIX}"\nCONFIG_LSM="{LSM_LIST}"\n')

    run("./scripts/kconfig/merge_config.sh -m .config hardened.config")
    run("make olddefconfig")

    log_header("PHASE 3: BUILD")
    ncpu = os.cpu_count() or 4
    run(f"time make -j{ncpu} KCFLAGS='-O2 -march=broadwell -mtune=broadwell'")
    kver = run("make -s kernelrelease", capture=True)

    log_header("PHASE 4: PACKAGING")
    pkg_dir = f"{workspace}/deb_staging"
    run(f"rm -rf {pkg_dir} && mkdir -p {pkg_dir}/DEBIAN {pkg_dir}/boot")
    run(f"make INSTALL_MOD_PATH={pkg_dir} modules_install")
    run(f"cp -v arch/x86/boot/bzImage {pkg_dir}/boot/vmlinuz-{kver}")
    run(f"cp -v vmlinux               {pkg_dir}/boot/vmlinux-{kver}")
    run(f"cp -v .config               {pkg_dir}/boot/config-{kver}")

    with open(f"{pkg_dir}/DEBIAN/control", "w") as f:
        f.write(f"Package: linux-image-grewalcc\nVersion: {ver}\nArchitecture: amd64\nMaintainer: {USER}\nDescription: v5.3.2\n")

    run(f"dpkg-deb --build {pkg_dir} {workspace}/linux-image-{kver}.deb")

    log_header("PHASE 5: DEPLOY")
    encoded = base64.b64encode(build_deploy_script(kver, f"linux-image-{kver}.deb", BOOT_ARGS).encode()).decode()
    common = f"--project {PROJECT} --zone {ZONE} --tunnel-through-iap"
    run(f"gcloud compute scp {common} {workspace}/linux-image-{kver}.deb {USER}@{INSTANCE}:/tmp/")
    run(f"gcloud compute ssh {USER}@{INSTANCE} {common} --command 'echo {encoded} | base64 -d | sudo bash'")

if __name__ == "__main__":
    main()
