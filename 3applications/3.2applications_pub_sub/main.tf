resource "google_project_iam_audit_config" "storage_audit_logs" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }

  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

resource "google_pubsub_topic" "wazuh_gcp_logs" {
  name    = "wazuh-gcp-logs"
  project = var.project_id
}

resource "google_pubsub_subscription" "wazuh_gcp_logs_sub" {
  name    = "wazuh-gcp-logs-sub"
  topic   = google_pubsub_topic.wazuh_gcp_logs.name
  project = var.project_id

  ack_deadline_seconds = 20

  message_retention_duration = "604800s"

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_logging_project_sink" "wazuh_sink" {
  name    = "wazuh-sink"
  project = var.project_id

  destination = "pubsub.googleapis.com/${google_pubsub_topic.wazuh_gcp_logs.id}"

  filter = <<-EOT
    (
      resource.type="cloud_function" 
      OR resource.type="api" 
      OR resource.type="api_gateway"
      OR resource.type="cloud_run_revision"
    )
    OR
    (
      resource.type="gcs_bucket"
      AND protoPayload.serviceName="storage.googleapis.com"
    )
    OR
    (
      logName:"cloudaudit.googleapis.com"
    )
  EOT

  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.wazuh_gcp_logs.name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.wazuh_sink.writer_identity
}

resource "google_service_account" "wazuh_log_reader" {
  account_id   = "wazuh-log-reader"
  display_name = "Wazuh Log Reader"
  project      = var.project_id
}

resource "google_project_iam_member" "wazuh_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.wazuh_log_reader.email}"
}

resource "google_service_account_key" "wazuh_key" {
  service_account_id = google_service_account.wazuh_log_reader.name
}

resource "local_file" "wazuh_key" {
  content  = base64decode(google_service_account_key.wazuh_key.private_key)
  filename = "${path.module}/wazuh.json"

  file_permission = "0600"
}

