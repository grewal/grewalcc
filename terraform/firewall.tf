resource "google_compute_firewall" "default_allow_iap_ssh" {
  project     = "mysides"
  name        = "default-allow-iap-ssh"
  network     = "default"
  direction   = "INGRESS"
  priority    = 1000
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
}
