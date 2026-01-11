output "vm_name" {
  description = "Name of the VM instance"
  value       = google_compute_instance.vm.name
}

output "vm_external_ip" {
  description = "External IP address of the VM"
  value       = google_compute_instance.vm.network_interface[0].access_config[0].nat_ip
}

output "vm_internal_ip" {
  description = "Internal IP address of the VM"
  value       = google_compute_instance.vm.network_interface[0].network_ip
}

output "vpc_network_name" {
  description = "Name of the VPC network"
  value       = google_compute_network.vpc.name
}

output "subnet_name" {
  description = "Name of the subnet"
  value       = google_compute_subnetwork.subnet.name
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "gcloud compute ssh ${google_compute_instance.vm.name} --zone=${var.zone} --project=${var.project_id}"
}

output "vm_private_name" {
  description = "Name of the private VM instance"
  value       = google_compute_instance.vm_private.name
}

output "vm_private_internal_ip" {
  description = "Internal IP address of the private VM"
  value       = google_compute_instance.vm_private.network_interface[0].network_ip
}

output "ssh_command_private" {
  description = "SSH command to connect to the private VM (requires IAP tunnel)"
  value       = "gcloud compute ssh ${google_compute_instance.vm_private.name} --zone=${var.zone} --project=${var.project_id} --tunnel-through-iap"
}

output "vpc_flow_logs_dataset" {
  description = "BigQuery dataset ID for VPC flow logs and audit logs"
  value       = google_bigquery_dataset.vpc_flow_logs.dataset_id
}

output "vpc_flow_logs_dataset_location" {
  description = "Location of the BigQuery dataset"
  value       = google_bigquery_dataset.vpc_flow_logs.location
}

output "vpc_flow_logs_sink_name" {
  description = "Name of the log sink (VPC flow logs and audit logs)"
  value       = google_logging_project_sink.vpc_flow_logs_sink.name
}

output "bigquery_query_example" {
  description = "Example BigQuery query to view recent logs"
  value       = "SELECT * FROM `${var.project_id}.${google_bigquery_dataset.vpc_flow_logs.dataset_id}.*` ORDER BY timestamp DESC LIMIT 100"
}

