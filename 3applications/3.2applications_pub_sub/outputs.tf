output "pubsub_topic_name" {
  description = "Name of the Pub/Sub topic"
  value       = google_pubsub_topic.wazuh_gcp_logs.name
}

output "pubsub_subscription_name" {
  description = "Name of the Pub/Sub subscription"
  value       = google_pubsub_subscription.wazuh_gcp_logs_sub.name
}

output "logging_sink_name" {
  description = "Name of the logging sink"
  value       = google_logging_project_sink.wazuh_sink.name
}

output "logging_sink_writer_identity" {
  description = "Writer identity of the logging sink"
  value       = google_logging_project_sink.wazuh_sink.writer_identity
}

output "wazuh_service_account_email" {
  description = "Email of the Wazuh service account"
  value       = google_service_account.wazuh_log_reader.email
}

output "wazuh_key_file_path" {
  description = "Path to the Wazuh service account key file"
  value       = local_file.wazuh_key.filename
  sensitive   = true
}

