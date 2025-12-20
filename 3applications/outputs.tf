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
  description = "External IP address of the Wazuh VM"
  value       = try(google_compute_instance.wazuh_vm.network_interface[0].access_config[0].nat_ip, "No external IP")
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

output "pubsub_topic" {
  description = "Pub/Sub topic for log export (if enabled)"
  value       = var.enable_log_export ? google_pubsub_topic.wazuh_logs[0].name : "Not enabled"
}

output "pubsub_subscription" {
  description = "Pub/Sub subscription for log ingestion (if enabled)"
  value       = var.enable_log_export ? google_pubsub_subscription.wazuh_logs_sub[0].name : "Not enabled"
}

output "instructions" {
  description = "Quick start instructions"
  value = <<-EOT
    
    ╔════════════════════════════════════════════════════════════════╗
    ║              Wazuh All-in-One Deployment Ready                 ║
    ╚════════════════════════════════════════════════════════════════╝
    
    1. Wait ~5-10 minutes for the VM to complete startup and Docker deployment
    
    2. Check VM startup progress:
       gcloud compute ssh ${google_compute_instance.wazuh_vm.name} --zone ${google_compute_instance.wazuh_vm.zone} --project ${var.project_id}
       sudo journalctl -u google-startup-scripts.service -f
    
    3. Verify Wazuh containers are running:
       gcloud compute ssh ${google_compute_instance.wazuh_vm.name} --zone ${google_compute_instance.wazuh_vm.zone} --project ${var.project_id}
       sudo docker ps
    
    4. Create SSH tunnel to access dashboard:
       gcloud compute ssh ${google_compute_instance.wazuh_vm.name} --zone ${google_compute_instance.wazuh_vm.zone} --project ${var.project_id} -- -L 5601:localhost:5601
    
    5. Access Wazuh Dashboard:
       URL: http://localhost:5601
       Username: admin
       Password: [Your wazuh_admin_password variable]
    
    6. Troubleshooting:
       - View Docker logs: sudo docker compose -f /opt/wazuh/docker-compose.yml logs -f
       - Restart containers: sudo docker compose -f /opt/wazuh/docker-compose.yml restart
    
    7. Cleanup:
       terraform destroy
    
    ℹ️  NOTE: Dashboard uses HTTP (not HTTPS) since SSH tunnel already encrypts traffic
    
  EOT
}

