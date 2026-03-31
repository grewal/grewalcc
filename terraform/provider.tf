terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
  backend "gcs" {
    bucket = "gcc-terraform-state-bucket"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = "mysides"
  region  = "us-south1"
}
