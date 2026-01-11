output "vm_name" {
  description = "Name of the Wazuh VM"
  value       = google_compute_instance.wazuh_vm.name
}

output "vm_zone" {
  description = "Zone of the Wazuh VM"
  value       = google_compute_instance.wazuh_vm.zone
}

output "vm_internal_ip" {
  description = "Internal IP address of the Wazuh VM"
  value       = google_compute_instance.wazuh_vm.network_interface[0].network_ip
}

output "vm_external_ip" {
  description = "External IPv4 address of the Wazuh VM"
  value       = try(google_compute_instance.wazuh_vm.network_interface[0].access_config[0].nat_ip, "No external IPv4")
}

output "vm_external_ipv6" {
  description = "External IPv6 address of the Wazuh VM"
  value       = try(google_compute_instance.wazuh_vm.network_interface[0].ipv6_access_config[0].external_ipv6, "No external IPv6")
}

output "vm_self_link" {
  description = "Self-link of the Wazuh VM"
  value       = google_compute_instance.wazuh_vm.self_link
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "gcloud compute ssh ${google_compute_instance.wazuh_vm.name} --zone ${google_compute_instance.wazuh_vm.zone} --project ${var.project_id}"
}

output "ssh_tunnel_command" {
  description = "SSH tunnel command to access Wazuh dashboard"
  value       = "gcloud compute ssh ${google_compute_instance.wazuh_vm.name} --zone ${google_compute_instance.wazuh_vm.zone} --project ${var.project_id} -- -L 5601:localhost:5601"
}

output "dashboard_url" {
  description = "Wazuh dashboard URL (accessible via SSH tunnel)"
  value       = "http://localhost:5601"
}

output "dashboard_username" {
  description = "Wazuh dashboard admin username"
  value       = "admin"
}

output "dashboard_password_note" {
  description = "Note about where the admin password is configured"
  value       = var.use_secret_manager ? "Password stored in Secret Manager: ${var.secret_name}" : "Password provided via wazuh_admin_password variable"
}

output "service_account_email" {
  description = "Service account email used by the VM"
  value       = google_service_account.wazuh_sa.email
}

output "network_name" {
  description = "Name of the VPC network"
  value       = var.use_default_vpc ? "default" : google_compute_network.wazuh_vpc[0].name
}

output "pubsub_integration_info" {
  description = "GCP Pub/Sub integration information"
  value = {
    project_id      = var.pubsub_project_id
    subscription_id = var.pubsub_subscription_id
    log_file        = "/var/log/gcp-wazuh.log"
    service_name    = "wazuh-gcp-pubsub.service"
    script_location = "/opt/wazuh-gcp-integration/gcp_pubsub_wazuh.py"
  }
}