#!/usr/bin/env python3
"""
upgrade_kernel.py 
"""

import subprocess, json, sys, os, base64, shutil, textwrap
from pathlib import Path
from urllib.request import urlopen

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INSTANCE    = "gcc-gem-a"
ZONE        = "us-south1-a"
PROJECT     = "mysides"
USER        = "ygrewal"

LVER_SUFFIX = "-grewalcc"
LSM_LIST    = "bpf,capability,landlock,lockdown,yama,integrity"

BOOT_ARGS = (
    f"lsm={LSM_LIST} "
    "bpf_lsm.enabled=1 "
    "isolcpus=1 "
    "nohz_full=1 "
    "rcu_nocbs=1 "
    "rcu_nocb_poll "
    "intel_pstate=disable "
    "pcie_aspm=off "
    "selinux=0 "
)

os.environ["LLVM"]     = "1"
os.environ["LLVM_IAS"] = "1"
os.environ["ARCH"]     = "x86_64"
os.environ["CC"]       = "clang-21"
os.environ["LD"]       = "ld.lld-21"

SCRIPT_DIR = Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# HARDENING_FRAGMENT
# ---------------------------------------------------------------------------
HARDENING_FRAGMENT: dict[str, str] = {
    # --- BLUEPRINT (/proc/config.gz) ---
    "CONFIG_IKCONFIG":                           "y",
    "CONFIG_IKCONFIG_PROC":                      "y",

    # --- TURN OFF CPU MITIGATIONS ---
    "CONFIG_CPU_MITIGATIONS":                    "n",
    "CONFIG_PAGE_TABLE_ISOLATION":               "n",
    "CONFIG_RETPOLINE":                          "n",
    "CONFIG_X86_SMAP":                           "n",
    "CONFIG_X86_SMEP":                           "n",

    # --- PERFORMANCE OVERLAYFS ---
    "CONFIG_OVERLAY_FS":                         "y",
    "CONFIG_OVERLAY_FS_REDIRECT_DIR":            "y",
    "CONFIG_OVERLAY_FS_METACOPY":                "y",

    # --- NETWORK SHIELD ---
    "CONFIG_BR_NETFILTER":                       "y",
    "CONFIG_BRIDGE_NETFILTER":                   "y",

    # --- SCHEDULER & PREEMPTION ---
    "CONFIG_PREEMPT_DYNAMIC":                    "y",
    "CONFIG_PREEMPT_VOLUNTARY":                  "n",
    "CONFIG_PREEMPT_LAZY":                       "y",
    "CONFIG_HZ_1000":                            "y",
    "CONFIG_HZ":                                 "1000",
    "CONFIG_NO_HZ_FULL":                         "y",
    "CONFIG_RCU_NOCB_CPU":                       "y",

    # --- eBPF / TETRAGON CO-RE ---
    "CONFIG_BPF":                                "y",
    "CONFIG_BPF_SYSCALL":                        "y",
    "CONFIG_BPF_JIT":                            "y",
    "CONFIG_BPF_LSM":                            "y",
    "CONFIG_DEBUG_INFO_BTF":                     "y",
    "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT": "y",
    "CONFIG_FTRACE":                             "y",
    "CONFIG_KALLSYMS_ALL":                       "y",

    # --- GCE HARDWARE & LUNGS ---
    "CONFIG_GVE":                                "y",
    "CONFIG_ZRAM":                               "y",
    "CONFIG_ZRAM_DEF_COMP_ZSTD":                 "y",
    "CONFIG_LTO_CLANG_THIN":                     "y",

    # --- HEADLESS PURGE ---
    "CONFIG_DRM":                                "n",
    "CONFIG_SOUND":                              "n",
    "CONFIG_WLAN":                               "n",
    "CONFIG_WIRELESS":                           "n",
    "CONFIG_BT":                                 "n",
    "CONFIG_I2C_PIIX4":                          "n",
    "CONFIG_MICROCODE":                          "n",
    "CONFIG_MODULE_SIG_FORCE":                   "n",
    "CONFIG_SERIO":                              "n",
    "CONFIG_SERIO_I8042":                        "n", # Kills the "Keylock active" warning
    "CONFIG_SERIO_RAW":                          "n", # Kills the "serio_raw" taint
    "CONFIG_MOUSE_PS2":                          "n", # Kills the PS/2 Mouse driver
    "CONFIG_KEYBOARD_ATKBD":                     "n", # Kills the Standard AT Keyboard driver
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_header(msg: str) -> None:
    print(f"\n{'='*80}\n{msg:^80}\n{'='*80}", flush=True)

def run(cmd: str, capture: bool = False) -> str | None:
    result = subprocess.run(
        cmd, shell=True, check=True, executable="/bin/bash",
        capture_output=capture, text=True)
    return result.stdout.strip() if capture else None

def validate_config(config_path: str) -> None:
    with open(config_path) as f:
        content = f.read()
    failures: list[str] = []

    CORE_BUILTIN = ["CONFIG_GVE", "CONFIG_DEBUG_INFO_BTF", "CONFIG_ZRAM",
                    "CONFIG_BPF_LSM", "CONFIG_IKCONFIG", "CONFIG_IKCONFIG_PROC",
                    "CONFIG_OVERLAY_FS"]

    MUST_EXIST = ["CONFIG_IP_NF_FILTER", "CONFIG_IP_NF_NAT", "CONFIG_BRIDGE", "CONFIG_VETH"]

    for cfg in CORE_BUILTIN:
        if f"{cfg}=y" not in content: failures.append(f"{cfg} (Must be =y)")

    for cfg in MUST_EXIST:
        if f"{cfg}=y" not in content and f"{cfg}=m" not in content:
            failures.append(f"{cfg} (Absent!)")

    if failures:
        print("\n[FATAL] Config validation failed:")
        for line in failures: print(f"  ✗ {line}")
        sys.exit(1)
    print("[OK] Config validated.")

def build_grub_python(kver: str) -> str:
    safe_kver = kver.replace("\\", "\\\\").replace("'", "\\'")
    lines = [
        "import re, sys",
        f"kver = '{safe_kver}'",
        "cfg = open('/boot/grub/grub.cfg').read()",
        "kp  = re.escape(kver)",
        "sub_pat = (r\"submenu\\s+(['\\\"])[^'\\\"]*Advanced options[^'\\\"]*\\1\" r\"\\s+\\$menuentry_id_option\\s+(['\\\"])([^'\\\"]+)\\2\")",
        "ent_pat = (r\"menuentry\\s+(['\\\"])[^'\\\"]*\" + kp + r\"[^'\\\"]*\\1\" r\"[^{]*\\$menuentry_id_option\\s+(['\\\"])([^'\\\"]+)\\2\")",
        "sub = re.search(sub_pat, cfg, re.DOTALL)",
        "ent = re.search(ent_pat, cfg, re.DOTALL)",
        "if sub and ent: print(sub.group(3) + '>' + ent.group(3)); sys.exit(0)",
        "if ent: print(ent.group(3)); sys.exit(0)",
        "print('FAILED'); sys.exit(1)"
    ]
    return "\n".join(lines) + "\n"

def build_deploy_script(kver: str, deb_name: str, boot_args: str) -> str:
    grub_py = build_grub_python(kver)
    grub_py_b64 = base64.b64encode(grub_py.encode()).decode()

    return textwrap.dedent(f"""\
        #!/bin/bash
        set -euo pipefail
        KVER="{kver}"
        DEB="{deb_name}"
        BOOT_ARGS="{boot_args}"

        # 1. PATH RESOLUTION
        REAL_HOME=$(getent passwd "{USER}" | cut -d: -f6)
        STAGING_DIR="${{REAL_HOME}}/install-temp"

        if [[ ! -f "${{STAGING_DIR}}/${{DEB}}" ]]; then
            echo "FATAL: Deb not found at ${{STAGING_DIR}}/${{DEB}}"
            exit 1
        fi

        # 2. THE PERMANENT LUNGS (udev logic)
        echo "[VM] Configuring persistent 2GB ZSTD Lungs via udev..."
        printf 'KERNEL=="zram0", ATTR{{comp_algorithm}}="zstd", ATTR{{disksize}}="2G", RUN+="/sbin/mkswap /dev/zram0", RUN+="/sbin/swapon -p 100 /dev/zram0"\\n' \
            | sudo tee /etc/udev/rules.d/99-sanctuary-zram.rules > /dev/null

        # 3. DOCKER BOOT OPTIMIZATION (systemd logic)
        echo "[VM] Optimizing Docker boot priority..."
        sudo mkdir -p /etc/systemd/system/docker.service.d
        printf "[Unit]\\nAfter=network-online.target\\nWants=network-online.target\\nDefaultDependencies=no\\n" \
            | sudo tee /etc/systemd/system/docker.service.d/override.conf > /dev/null

        # 4. THE NETWORK SHIELD
        echo "[VM] Silencing bridge noise..."
        sysctl -w net.bridge.bridge-nf-call-iptables=1 || true

        # 5. INSTALLATION
        echo "[VM] Installing Kernel..."
        ionice -c 3 dpkg -i "${{STAGING_DIR}}/${{DEB}}"
        ionice -c 3 update-initramfs -c -k "${{KVER}}"

        # 6. GRUB CONFIGURATION
        mkdir -p /etc/default/grub.d
        printf 'GRUB_CMDLINE_LINUX_DEFAULT="%s"\\n' "${{BOOT_ARGS}}" > /etc/default/grub.d/99-grewalcc.cfg
        sed -i 's|^GRUB_DEFAULT=.*|GRUB_DEFAULT=saved|' /etc/default/grub
        update-grub

        # 7. BOOT ORCHESTRATION
        echo '{grub_py_b64}' | base64 -d | python3 > "${{STAGING_DIR}}/grub_ids"

        GRUB_IDS=$(cat "${{STAGING_DIR}}/grub_ids")
        grub-reboot "${{GRUB_IDS}}"

        echo "[VM] Rebooting to ${{KVER}} in 5s..."
        sleep 5; reboot
    """)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log_header("PHASE 0: BUILD READINESS")
    baseline = SCRIPT_DIR / "zabbly_baseline.config"
    if not baseline.exists(): sys.exit(1)

    log_header("PHASE 1: SOURCE")
    with urlopen("https://www.kernel.org/releases.json") as r:
        data = json.loads(r.read().decode())
    rel = next((r for r in data["releases"] if r["moniker"] == "mainline"), None)
    ver = rel["version"]; url = rel["source"]
    workspace = Path.home() / "kernel_orchestrator_build"; workspace.mkdir(exist_ok=True)
    os.chdir(workspace)
    tar_path = workspace / f"linux-{ver}.tar.gz"; src_path = workspace / f"linux-{ver}"
    if not tar_path.exists(): run(f"wget -q -O {tar_path} {url}")
    if not src_path.is_dir():
        src_path.mkdir(); run(f"tar -xf {tar_path} -C {src_path} --strip-components=1")
    os.chdir(src_path)

    log_header("PHASE 2: CONFIG")
    shutil.copy(baseline, src_path / ".config")
    run("make olddefconfig")
    fragment_path = src_path / "sanctuary.config"
    with open(fragment_path, "w") as f:
        for k, v in HARDENING_FRAGMENT.items(): f.write(f"{k}={v}\n")
        f.write(f'CONFIG_LOCALVERSION="{LVER_SUFFIX}"\nCONFIG_LSM="{LSM_LIST}"\n')
    run(f"./scripts/kconfig/merge_config.sh .config {fragment_path}")
    run("make olddefconfig")
    validate_config(str(src_path / ".config"))

    log_header("PHASE 3: BUILD")
    ncpu = os.cpu_count() or 4
    run(f"time make -j{ncpu} KCFLAGS='-O2 -march=broadwell -mtune=broadwell'")
    kver = run("make -s kernelrelease", capture=True)

    log_header("PHASE 4: PACKAGING & STRIP")
    pkg_dir = workspace / "deb_staging"; run(f"rm -rf {pkg_dir}")
    (pkg_dir / "DEBIAN").mkdir(parents=True); (pkg_dir / "boot").mkdir(parents=True)
    run(f"make INSTALL_MOD_PATH={pkg_dir} modules_install")
    run(f"find {pkg_dir} -name '*.ko' -exec llvm-strip-21 --strip-debug {{}} +")
    run(f"cp -v arch/x86/boot/bzImage {pkg_dir}/boot/vmlinuz-{kver}")
    run(f"cp -v .config               {pkg_dir}/boot/config-{kver}")

    with open(pkg_dir / "DEBIAN" / "control", "w") as f:
        f.write(f"Package: linux-image-grewalcc\nVersion: {ver}\nArchitecture: amd64\nMaintainer: {USER}\Kernel 7.0.0-rc7\n")

    deb_path = workspace / f"linux-image-{kver}.deb"
    run(f"dpkg-deb --build {pkg_dir} {deb_path}")

    log_header("PHASE 5: DEPLOY")
    # Ensure ~/install-temp exists on the VM before SCP
    common = f"--project {PROJECT} --zone {ZONE} --tunnel-through-iap"
    run(f"gcloud compute ssh {USER}@{INSTANCE} {common} --command 'mkdir -p ~/install-temp'")
    run(f"gcloud compute scp {common} {deb_path} {USER}@{INSTANCE}:~/install-temp/")

    encoded = base64.b64encode(build_deploy_script(kver, deb_path.name, BOOT_ARGS).encode()).decode()
    run(f"gcloud compute ssh {USER}@{INSTANCE} {common} --command 'echo {encoded} | base64 -d | sudo bash'")

if __name__ == "__main__": main()
