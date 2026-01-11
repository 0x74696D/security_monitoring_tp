# Random suffix for globally unique resource names
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  bucket_name = var.bucket_name != "" ? var.bucket_name : "sec-lab-images-${var.project_id}-${random_id.suffix.hex}"
  function_name = "sec-lab-api-${random_id.suffix.hex}"
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "identitytoolkit.googleapis.com",
    "apigateway.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
    "storage.googleapis.com",
    "firestore.googleapis.com",
    "serviceusage.googleapis.com",
    "servicecontrol.googleapis.com",
    "servicemanagement.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

# Identity Platform Configuration //used for user authentication
resource "google_identity_platform_config" "default" {
  provider = google-beta
  project  = var.project_id

  sign_in {
    email {
      enabled = true
    }
  }

  depends_on = [google_project_service.required_apis]
}

# Firestore Database //used for metadata storage
resource "google_firestore_database" "default" {
  count    = var.enable_firestore ? 1 : 0
  project  = var.project_id
  name     = "(default)"
  location_id = var.region
  type     = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.required_apis]
}

# Cloud Storage bucket for images //used for storing images
resource "google_storage_bucket" "images" {
  name          = local.bucket_name
  location      = var.region
  project       = var.project_id
  force_destroy = true

  uniform_bucket_level_access = true

  cors {
    origin          = ["*"]
    method          = ["GET", "POST", "PUT", "DELETE"]
    response_header = ["*"]
    max_age_seconds = 3600
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required_apis]
}

# Service Account for Cloud Functions //used for granting permissions to the cloud function
resource "google_service_account" "function_sa" {
  account_id   = "sec-lab-function-${random_id.suffix.hex}"
  display_name = "Security Lab Function Service Account"
  project      = var.project_id
}

# Grant Storage Object Admin to function SA //used for granting permissions to the cloud function to access the storage bucket
resource "google_storage_bucket_iam_member" "function_storage_access" {
  bucket = google_storage_bucket.images.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.function_sa.email}"
}

# Grant Firestore User to function SA //used for granting permissions to the cloud function to access the firestore database
resource "google_project_iam_member" "function_firestore_access" {
  count   = var.enable_firestore ? 1 : 0
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

# Grant Identity Platform User to function SA (for token verification) //used for granting permissions to the cloud function to access the identity platform
resource "google_project_iam_member" "function_identity_access" {
  project = var.project_id
  role    = "roles/identitytoolkit.viewer"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

# Create zip archive of function code //used for uploading the function code to the cloud function
data "archive_file" "function_source" {
  type        = "zip"
  source_dir  = "${path.module}/functions"
  output_path = "${path.module}/functions.zip"
}

# Upload function source to GCS //used for uploading the function code to the cloud function
resource "google_storage_bucket" "function_source" {
  name     = "sec-lab-functions-${var.project_id}-${random_id.suffix.hex}"
  location = var.region
  project  = var.project_id

  force_destroy = true

  depends_on = [google_project_service.required_apis]
}

# Upload function source to GCS //used for uploading the function code to the cloud function
resource "google_storage_bucket_object" "function_source" {
  name   = "function-source-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function_source.output_path
}

# Cloud Function (2nd gen) //used for hosting the api
resource "google_cloudfunctions2_function" "api" {
  name        = local.function_name
  location    = var.region
  project     = var.project_id
  description = "Security Lab API Function"

  build_config {
    runtime     = "python311"
    entry_point = "handle_request"
    
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    min_instance_count = 0
    available_memory   = "256M"
    timeout_seconds    = 60

    service_account_email = google_service_account.function_sa.email

    environment_variables = {
      PROJECT_ID                            = var.project_id
      BUCKET_NAME                           = google_storage_bucket.images.name
      ENABLE_FIRESTORE                      = var.enable_firestore
      LAB_MODE_SKIP_OWNERSHIP_CHECK         = var.lab_mode_skip_object_ownership_check
      LAB_MODE_WEAK_TOKEN_VALIDATION        = var.lab_mode_weak_token_validation
      ENVIRONMENT                           = var.environment
    }

    ingress_settings = "ALLOW_ALL"
  }

  depends_on = [
    google_project_service.required_apis,
    google_storage_bucket_object.function_source,
  ]
}

# Allow unauthenticated invocation (API Gateway will handle auth) //used for allowing unauthenticated access to the api
resource "google_cloud_run_service_iam_member" "function_invoker" {
  project  = google_cloudfunctions2_function.api.project
  location = google_cloudfunctions2_function.api.location
  service  = google_cloudfunctions2_function.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# API Gateway Configuration //used for hosting the api
resource "google_api_gateway_api" "api" {
  provider = google-beta
  project  = var.project_id
  api_id   = "sec-lab-api-${random_id.suffix.hex}"

  depends_on = [google_project_service.required_apis]
}

# API Gateway Configuration //used for hosting the api
resource "google_api_gateway_api_config" "api_config" {
  provider      = google-beta
  project       = var.project_id
  api           = google_api_gateway_api.api.api_id
  api_config_id = "config-${random_id.suffix.hex}"

  openapi_documents {
    document {
      path = "openapi.yaml"
      contents = base64encode(templatefile("${path.module}/openapi.yaml", {
        function_url = google_cloudfunctions2_function.api.service_config[0].uri
        project_id   = var.project_id
      }))
    }
  }

  gateway_config {
    backend_config {
      google_service_account = google_service_account.function_sa.email
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    google_api_gateway_api.api,
    google_cloudfunctions2_function.api,
  ]
}

# API Gateway Configuration //used for hosting the api
resource "google_api_gateway_gateway" "gateway" {
  provider   = google-beta
  project    = var.project_id
  region     = var.region
  gateway_id = "sec-lab-gateway-${random_id.suffix.hex}"
  api_config = google_api_gateway_api_config.api_config.id

  depends_on = [google_api_gateway_api_config.api_config]
}