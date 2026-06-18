output "vm_external_ip" {
  description = "The public IP address of the VM"
  value       = google_compute_address.grewalcc_static_ip.address
}

output "vm_internal_ip" {
  description = "The internal IP address of the VM"
  value       = google_compute_instance.gcc_gem_a.network_interface.0.network_ip
}

output "ssh_command" {
  description = "Command to SSH into the machine"
  value       = "gcloud compute ssh ${google_compute_instance.gcc_gem_a.name} --zone ${var.zone} --project ${var.project_id}"
}
