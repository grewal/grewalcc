# Create a Custom VPC (decoupled from Google's global default)
resource "google_compute_network" "custom_vpc" {
  name                    = "mysides-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false # FAANG Standard: No automatic subnets
}

# Create a specific subnet just for Oregon
resource "google_compute_subnetwork" "west_subnet" {
  name          = "mysides-west-subnet"
  ip_cidr_range = "10.0.1.0/24" # A clean, isolated IP block
  region        = var.region
  network       = google_compute_network.custom_vpc.id
  project       = var.project_id
}
