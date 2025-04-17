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
  region  = "us-central1"
  # Zone can be configured here too, or within specific resources like the VM
  # zone    = "us-central1-f"

  # Credentials will be automatically sourced from
  # gcloud auth application-default login (ADC)
}
