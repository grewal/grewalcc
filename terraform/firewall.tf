# firewall.tf

# Allows TCP port 80 from any source to instances tagged "http-server"
resource "google_compute_firewall" "default_allow_http" {
  project     = "mysides"
  name        = "default-allow-http"
  network     = "default" # Corresponds to the network URI in gcloud output
  direction   = "INGRESS"
  priority    = 1000
  description = "Allow HTTP traffic from anywhere"

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["http-server"]
}

# Allows TCP and UDP port 443 from any source to instances tagged "https-server"
resource "google_compute_firewall" "default_allow_https" {
  project     = "mysides"
  name        = "default-allow-https"
  network     = "default"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  allow {
    protocol = "udp" # Added for QUIC support for HTTP 3
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["https-server"]
}

# Allows TCP from Google health checkers (IPv4) to instances tagged "lb-health-check"
resource "google_compute_firewall" "default_allow_health_check" {
  project     = "mysides"
  name        = "default-allow-health-check"
  network     = "default"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    # No ports specified means all TCP ports, matching gcloud output
  }

  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
    "209.85.152.0/22",
    "209.85.204.0/22",
  ]
  target_tags = ["lb-health-check"]
}

# Allows TCP from Google health checkers (IPv6) to instances tagged "lb-health-check"
resource "google_compute_firewall" "default_allow_health_check_ipv6" {
  project     = "mysides"
  name        = "default-allow-health-check-ipv6"
  network     = "default"
  direction   = "INGRESS"
  priority    = 1000

  allow {
    protocol = "tcp"
    # No ports specified means all TCP ports
  }

  # Note: Using source_ranges for IPv6 addresses
  source_ranges = [
    "2600:1901:8001::/48",
    "2600:2d00:1:b029::/64",
  ]
  target_tags = ["lb-health-check"]
}
