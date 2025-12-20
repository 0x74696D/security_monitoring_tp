terraform {
  required_version = ">= 1.0"
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Cloud Run Service with IAM authentication
resource "google_cloud_run_v2_service" "vuln_app" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = "${var.image_repository}:${var.image_tag}"

      # Resource limits
      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
      }

      # Health check probe (optional but recommended)
      startup_probe {
        initial_delay_seconds = 0
        timeout_seconds      = 1
        period_seconds       = 3
        failure_threshold    = 1
        tcp_socket {
          port = 8080
        }
      }
    }

    # Scaling configuration for request-based scaling
    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    # Timeout configuration
    timeout = "${var.timeout}s"

    # Service account (uses default compute service account if not specified)
    # You can create a custom service account and specify it here
    # service_account = google_service_account.cloudrun_sa.email
  }

  # Traffic routing - 100% to latest revision
  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  lifecycle {
    ignore_changes = [
      # Ignore changes to the image tag if you want to manage deployments separately
      # template[0].containers[0].image,
    ]
  }
}

# IAM Policy - No public access (IAM authentication required)
# This explicitly denies unauthenticated access
resource "google_cloud_run_service_iam_member" "noauth" {
  location = google_cloud_run_v2_service.vuln_app.location
  service  = google_cloud_run_v2_service.vuln_app.name
  role     = "roles/run.invoker"
  member   = "allUsers"
  
  # This effectively prevents the binding by adding a condition that's always false
  # Remove this resource entirely to prevent any public access
  count = 0  # Set to 0 to disable public access
}

# Grant Cloud Run Invoker role to specific members
# Add members to var.allowed_members to grant them access
resource "google_cloud_run_service_iam_member" "authorized_invokers" {
  for_each = toset(var.allowed_members)
  
  location = google_cloud_run_v2_service.vuln_app.location
  service  = google_cloud_run_v2_service.vuln_app.name
  role     = "roles/run.invoker"
  member   = each.value
}