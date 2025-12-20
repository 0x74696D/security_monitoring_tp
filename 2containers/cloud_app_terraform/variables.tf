variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "bounc-473410"
}

variable "region" {
  description = "The GCP region for Cloud Run"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "The name of the Cloud Run service"
  type        = string
  default     = "vuln-app-service"
}

variable "image_repository" {
  description = "The container image repository"
  type        = string
  default     = "us-central1-docker.pkg.dev/bounc-473410/lab-test-repo/vuln-app"
}

variable "image_tag" {
  description = "The image tag to deploy (use 'latest' for the most recent image)"
  type        = string
  default     = "latest"
}

variable "min_instances" {
  description = "Minimum number of instances"
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Maximum number of instances"
  type        = number
  default     = 1
}

variable "cpu" {
  description = "Number of CPUs to allocate"
  type        = string
  default     = "1"
}

variable "memory" {
  description = "Memory to allocate (e.g., '512Mi', '1Gi')"
  type        = string
  default     = "512Mi"
}

variable "timeout" {
  description = "Request timeout in seconds"
  type        = number
  default     = 300
}

variable "allowed_members" {
  description = "List of members who can invoke the service (e.g., 'user:email@example.com', 'serviceAccount:sa@project.iam.gserviceaccount.com')"
  type        = list(string)
  default     = []
}

