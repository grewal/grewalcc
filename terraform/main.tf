# Create a dedicated Service Account just for this VM
resource "google_service_account" "vm_sa" {
  account_id   = "gcc-gem-a-sa"
  display_name = "Service Account for GCC Gem A VM"
  project      = var.project_id
}

resource "google_compute_address" "grewalcc_static_ip" {
  name    = "grewalcc-static-ip-external"
  project = var.project_id
  region  = var.region

  lifecycle {
    ignore_changes = [description]
  }
}

resource "google_compute_instance" "gcc_gem_a" {
  project      = var.project_id
  name         = "gcc-gem-a"
  machine_type = "e2-micro"
  zone         = var.zone

  tags = ["http-server", "https-server"]

  labels = {
    "goog-ops-agent-policy" = "v2-x86-template-1-4-0"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-13"
      size  = 30 
      type  = "pd-standard" 
    }
    auto_delete = true
    device_name = "gcc-gem-a"
  }

  network_interface {
    network    = google_compute_network.custom_vpc.id
    subnetwork = google_compute_subnetwork.west_subnet.id
    nic_type   = "GVNIC"

    access_config {
      nat_ip = google_compute_address.grewalcc_static_ip.address
    }
  }

  service_account {
    email  = google_service_account.vm_sa.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = false
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    provisioning_model  = "STANDARD"
    on_host_maintenance = "MIGRATE"
    automatic_restart   = true
    preemptible         = false
  }

  deletion_protection = false
  can_ip_forward      = false

  metadata = {
    enable-osconfig = "TRUE"
    enable-oslogin  = "TRUE" 
  }

  # ==========================================
  # THE AUTOMATED BOOTSTRAPPER
  # ==========================================
  metadata_startup_script = <<-EOF
    #!/bin/bash
    # 0. Set up logging so we can troubleshoot if needed
    exec > /var/log/bootstrap-script.log 2>&1
    echo "Starting automated bootstrap for CSUEB Kernel Dev..."

    MAIN_USER="ygrewal_gmail_com"

    # 1. Update & Essential Utilities (Added lsb-release)
    apt-get update
    apt-get upgrade -y
    apt-get install -y curl wget git tmux htop jq vim unzip apt-transport-https ca-certificates gnupg lsb-release

    # 2. Kernel Compilation & C++ Base
    apt-get install -y build-essential cmake pkg-config gdb \
        libncurses-dev bison flex libssl-dev libelf-dev bc rsync kmod cpio

    # 3. LLVM/Clang Nightly (Bleeding Edge 22+)
    wget https://apt.llvm.org/llvm.sh
    chmod +x llvm.sh
    ./llvm.sh all
    
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-22 100
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-22 100
    update-alternatives --install /usr/bin/cc cc /usr/bin/clang-22 100
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-22 100
    update-alternatives --install /usr/bin/lld lld /usr/bin/lld-22 100

    # 4. The Go Toolchain
    apt-get install -y golang

    # 5. The Rust Toolchain
    su - $MAIN_USER -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"

    # 6. Docker Engine & Permissions
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    usermod -aG docker $MAIN_USER

    # 7. HashiCorp Terraform
    wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
    apt-get update
    apt-get install -y terraform

    # 8. Verification & Outro
    echo "========================================"
    echo "TOOLCHAIN VERSIONS INSTALLED:"
    echo "========================================"
    clang --version | head -n 1
    go version
    su - $MAIN_USER -c "cargo --version"
    terraform version | head -n 1
    docker --version
    echo "========================================"
    echo "Bootstrap complete! The server is ready."
  EOF

  lifecycle {
    prevent_destroy = false 
    ignore_changes = [labels]
  }
}
