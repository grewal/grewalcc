# provider.tf

terraform {
  # Required provider configuration
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # Minimum Terraform version compatibility
  required_version = ">= 1.0"

  # GCS Backend Configuration
  backend "gcs" {
    bucket = "gcc-terraform-state-bucket"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = "mysides"
  region  = "us-west1"
}
