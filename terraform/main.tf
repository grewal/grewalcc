resource "google_compute_address" "grewalcc_static_ip" {
  name    = "grewalcc-static-ip-external"
  project = "mysides"
  region  = "us-south1"
}

resource "google_compute_instance" "gcc_gem_a" {
  project      = "mysides"
  name         = "gcc-gem-a"
  machine_type = "e2-micro"
  zone         = "us-south1-a"

  boot_disk {
    auto_delete = true
    initialize_params {
      image = "debian-cloud/debian-13"
      size  = 15
      type  = "pd-balanced"
    }
  }

  network_interface {
    network    = "default"
    subnetwork = "default"
    nic_type   = "GVNIC"
    access_config {
      nat_ip = google_compute_address.grewalcc_static_ip.address
    }
  }

  metadata = {
    enable-osconfig    = "TRUE"
    serial-port-enable = "true"
  }

  service_account {
    email  = "62940940662-compute@developer.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = false
    enable_vtpm                  = true
    enable_integrity_monitoring = true
  }

  scheduling {
    provisioning_model  = "STANDARD"
    on_host_maintenance = "MIGRATE"
  }

  deletion_protection = false
  can_ip_forward      = true
}
