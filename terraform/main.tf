# terraform/main.tf

resource "google_compute_address" "grewalcc_static_ip" {
  name    = "grewalcc-static-ip-external"
  project = "mysides"
  region  = "us-central1"
  lifecycle { ignore_changes = [description] }
}

resource "google_compute_instance" "gcc_gem_a" {
  project      = "mysides"
  name         = "gcc-gem-a"
  machine_type = "e2-micro"
  zone         = "us-central1-f"

  tags = ["http-server", "https-server", "lb-health-check"]

  labels = {
    # REMOVED: "goog-ops-agent-policy" (Resource Rationalization)
    "os_family"             = "debian"
    "os_version"            = "trixie"
    "kernel_target"         = "zabbly-6-17-11"
    "provisioned_at"        = "2025-12-12"
    "environment"           = "dev"
    "owner"                 = "monty"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-13"
      size  = 15
      type  = "pd-balanced"
    }
    auto_delete = true
    device_name = "gcc-gem-a"
  }

  network_interface {
    network    = "default"
    subnetwork = "default"
    network_ip = "10.128.0.22"
    access_config {
        nat_ip = google_compute_address.grewalcc_static_ip.address
    }
  }

  metadata = {
    enable-osconfig = "TRUE"
    
    # 1. EMERGENCY ACCESS: Keep this TRUE
    serial-port-enable = "true"
    
    # 2. DISABLE LOGGING: Stop Google from wasting CPU scraping the console.
    serial-port-logging-enable = "false"
    
    ssh-keys = <<-EOT
      ygrewal:ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMvD1dCerU4ca4lwca9SoK1iMs921ibp3HHiut8U7A9agI0NU+JvBQf3nWe1Qd7ELMSx7ETUFV4B1BbTiMBaIdo= google-ssh {"userName":"ygrewal@gmail.com","expireOn":"2025-03-09T06:45:13+0000"}
      ygrewal:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiGRuNooUjZMzl7KScyjZGe8VpXPEnNuL/li/HWI3EIYZR8MUWgMxT4jjhACWPpC/9erzCnO90WW6iRpbcu8meo0spGccNJ+P8PN+fBzs/qAFRPLhPEI9V18cmsZ/oCzTdS8Inz0WI32SH3RPMNahRDMckT+29E+AhrMuwKhgr8Ax5nVvoh/q+0RhTo4ou65eHKiDppBVPvU9AF0IfVjItETXGOXzp5oCHjgGSAXT68tIqgpwiIWsg4ZKTTPigpnBf9zWg5F1/3lzIbkFLzT5Tl66Kz1/q1s7mMh/vdNAjHL4l1ViCC93pPP3q7+P8ng1K11jlpo+zXDIw+WEPmYOT google-ssh {"userName":"ygrewal@gmail.com","expireOn":"2025-03-09T06:45:17+0000"}
    EOT
  }

  service_account {
    email  = "62940940662-compute@developer.gserviceaccount.com"
    scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/trace.append"
    ]
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

   lifecycle {
     prevent_destroy = false 
     ignore_changes = [
        labels["goog-ops-agent-policy"], 
        metadata["ssh-keys"],
     ]
   }
}
