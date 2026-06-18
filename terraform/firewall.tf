resource "google_compute_firewall" "custom_allow_http" {
  project     = var.project_id
  name        = "custom-allow-http"
  network     = google_compute_network.custom_vpc.id # Changed
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["http-server"]
}

resource "google_compute_firewall" "custom_allow_https" {
  project     = var.project_id
  name        = "custom-allow-https"
  network     = google_compute_network.custom_vpc.id # Changed
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  allow {
    protocol = "udp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["https-server"]
}

resource "google_compute_firewall" "custom_allow_iap_ssh" {
  project     = var.project_id
  name        = "custom-allow-iap-ssh"
  network     = google_compute_network.custom_vpc.id # Changed
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"] 
}
