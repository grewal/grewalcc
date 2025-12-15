# terraform/firewall.tf

# ------------------------------------------------------------------------------
# 1. THE IRON GATES (Allow Ingress)
# ------------------------------------------------------------------------------

resource "google_compute_firewall" "allow_http" {
  project     = "mysides"
  name        = "strict-allow-http"
  network     = "default"
  priority    = 1000
  direction   = "INGRESS"
  target_tags = ["http-server"]

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_https" {
  project     = "mysides"
  name        = "strict-allow-https"
  network     = "default"
  priority    = 1000
  direction   = "INGRESS"
  target_tags = ["https-server"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  allow {
    protocol = "udp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
}

# STRICT: Allow Health Checks (IPv4)
resource "google_compute_firewall" "allow_health_checks_ipv4" {
  project     = "mysides"
  name        = "strict-allow-health-checks-ipv4"
  network     = "default"
  priority    = 1000
  direction   = "INGRESS"
  target_tags = ["lb-health-check"]

  allow {
    protocol = "tcp"
  }
  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
    "209.85.152.0/22",
    "209.85.204.0/22"
  ]
}

# STRICT: Allow Health Checks (IPv6)
resource "google_compute_firewall" "allow_health_checks_ipv6" {
  project     = "mysides"
  name        = "strict-allow-health-checks-ipv6"
  network     = "default"
  priority    = 1000
  direction   = "INGRESS"
  target_tags = ["lb-health-check"]

  allow {
    protocol = "tcp"
  }
  source_ranges = [
    "2600:1901:8001::/48",
    "2600:2d00:1:b029::/64"
  ]
}

resource "google_compute_firewall" "allow_iap_ssh" {
  project   = "mysides"
  name      = "strict-allow-iap-ssh"
  network   = "default"
  priority  = 1000
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
}

# ------------------------------------------------------------------------------
# 2. THE INTERNAL LOCKDOWN
# ------------------------------------------------------------------------------

resource "google_compute_firewall" "deny_all_internal" {
  project     = "mysides"
  name        = "paranoid-deny-internal"
  network     = "default"
  priority    = 60000
  direction   = "INGRESS"
  source_ranges = ["10.128.0.0/9"]

  deny {
    protocol = "all"
  }
}
