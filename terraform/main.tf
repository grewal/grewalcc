# main.tf

resource "google_compute_instance" "gcc_gem_a" {
  project      = "mysides" # Explicitly set project, although inherited from provider
  name         = "gcc-gem-a"
  machine_type = "e2-micro" # Matches "projects/mysides/zones/us-central1-f/machineTypes/e2-micro"
  zone         = "us-central1-f"

  tags = ["http-server", "https-server", "lb-health-check"]

  labels = {
    "goog-ops-agent-policy" = "v2-x86-template-1-4-0"
  }

  boot_disk {
    initialize_params {
      # Image family derived from JSON licenses/name
      image = "debian-cloud/debian-12"
      size  = 15 # Matches "diskSizeGb": "15"
      # Confirmed Balanced Persistent Disk
      type = "pd-balanced"
    }
    # Match "autoDelete": true from the JSON disk info
    auto_delete = true
    # Match "deviceName": "gcc-gem-a" from the JSON disk info
    device_name = "gcc-gem-a"
  }

  network_interface {
    # Match "network": ".../global/networks/default"
    network = "default"
    # Match "subnetwork": ".../regions/us-central1/subnetworks/default"
    subnetwork = "default"

    # Match "networkIP": "10.128.0.22"
    # Set the specific internal IP to ensure consistency with the existing setup
    network_ip = "10.128.0.22"

    access_config {
      # This empty block requests an ephemeral external IP, matching:
      # "natIP": "35.209.221.97" (Ephemeral)
      # "networkTier": "STANDARD" (Default for ephemeral)
    }
  }

  # Match "metadata" block from JSON, including ssh-keys
  metadata = {
    enable-osconfig = "TRUE"
    # IMPORTANT: Include existing SSH keys from JSON to match state for import
    ssh-keys = <<-EOT
      ygrewal:ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMvD1dCerU4ca4lwca9SoK1iMs921ibp3HHiut8U7A9agI0NU+JvBQf3nWe1Qd7ELMSx7ETUFV4B1BbTiMBaIdo= google-ssh {"userName":"ygrewal@gmail.com","expireOn":"2025-03-09T06:45:13+0000"}
      ygrewal:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiGRuNooUjZMzl7KScyjZGe8VpXPEnNuL/li/HWI3EIYZR8MUWgMxT4jjhACWPpC/9erzCnO90WW6iRpbcu8meo0spGccNJ+P8PN+fBzs/qAFRPLhPEI9V18cmsZ/oCzTdS8Inz0WI32SH3RPMNahRDMckT+29E+AhrMuwKhgr8Ax5nVvoh/q+0RhTo4ou65eHKiDppBVPvU9AF0IfVjItETXGOXzp5oCHjgGSAXT68tIqgpwiIWsg4ZKTTPigpnBf9zWg5F1/3lzIbkFLzT5Tl66Kz1/q1s7mMh/vdNAjHL4l1ViCC93pPP3q7+P8ng1K11jlpo+zXDIw+WEPmYOT google-ssh {"userName":"ygrewal@gmail.com","expireOn":"2025-03-09T06:45:17+0000"}
    EOT
  }

  # Match "serviceAccounts": [ { "email": "...", "scopes": [...] } ]
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

  # Match "shieldedInstanceConfig" / "shieldedVmConfig"
  shielded_instance_config {
    enable_secure_boot          = false # Matches "enableSecureBoot": false
    enable_vtpm                 = true  # Matches "enableVtpm": true
    enable_integrity_monitoring = true  # Matches "enableIntegrityMonitoring": true
  }

  # Match "scheduling" block details
  scheduling {
    provisioning_model  = "STANDARD"  # Matches "provisioningModel": "STANDARD"
    on_host_maintenance = "MIGRATE"   # Matches "onHostMaintenance": "MIGRATE"
    automatic_restart   = true        # Matches "automaticRestart": true
    preemptible         = false       # Matches "preemptible": false
  }

  # Match "deletionProtection": false
  deletion_protection = false

  # Match "canIpForward": false
  can_ip_forward = false

  # Match "displayDevice": { "enableDisplay": false }
  # Terraform handles this implicitly or via advanced_machine_features if needed.
  # Let's omit explicit advanced_machine_features unless plan shows a diff.

   lifecycle {
     prevent_destroy = true // Optional: Add extra safety against accidental destruction later.
     ignore_changes = [
       // Example: If OS Login *also* manages keys and causes conflicts with metadata:
       // metadata["ssh-keys"],
       // Example: If GCP adds labels automatically we don't care about:
        labels,
        metadata["ssh-keys"],
     ]
   }
}
