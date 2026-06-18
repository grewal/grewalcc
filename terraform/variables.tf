variable "project_id" {
  description = "The ID of the GCP project"
  type        = string
  default     = "mysides"
}

variable "region" {
  description = "The default compute region"
  type        = string
  default     = "us-west1"
}

variable "zone" {
  description = "The default compute zone"
  type        = string
  default     = "us-west1-a"
}
