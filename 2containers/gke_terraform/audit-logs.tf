# Enable Kubernetes API audit logging at project level
# This captures kubectl exec and other data access events
resource "google_project_iam_audit_config" "gke_audit" {
  project = var.project_id
  service = "container.googleapis.com"

  # Admin activity (free, enabled by default)
  audit_log_config {
    log_type = "ADMIN_READ"
  }

  # Data access logs (captures kubectl exec, get, list, etc.)
  # Warning: This will increase Cloud Logging costs
  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

