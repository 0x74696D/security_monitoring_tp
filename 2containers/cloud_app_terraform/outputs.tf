output "service_url" {
  description = "The URL of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.vuln_app.uri
}

output "service_name" {
  description = "The name of the Cloud Run service"
  value       = google_cloud_run_v2_service.vuln_app.name
}

output "service_id" {
  description = "The full resource ID of the Cloud Run service"
  value       = google_cloud_run_v2_service.vuln_app.id
}

output "location" {
  description = "The location where the service is deployed"
  value       = google_cloud_run_v2_service.vuln_app.location
}

output "latest_revision" {
  description = "The latest revision name"
  value       = google_cloud_run_v2_service.vuln_app.latest_ready_revision
}

output "curl_command" {
  description = "Example curl command to invoke the service with authentication"
  value       = "curl -H 'Authorization: Bearer $(gcloud auth print-identity-token)' ${google_cloud_run_v2_service.vuln_app.uri}"
}

