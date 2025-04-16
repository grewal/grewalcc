# provider.tf

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0" # Use a recent version of the GCP provider
    }
  }
  required_version = ">= 1.0" # Specify minimum Terraform version compatibility
}

provider "google" {
  project = "mysides"
  region  = "us-central1"
  # Zone can be configured here too, or within specific resources like the VM
  # zone    = "us-central1-f"

  # Credentials will be automatically sourced from
  # gcloud auth application-default login (ADC)
}
