variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Environment name (must be 'lab' to enable lab modes)"
  type        = string
  default     = "lab"

  validation {
    condition     = contains(["lab", "dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: lab, dev, staging, prod"
  }
}

variable "ip_allowlist" {
  description = "List of CIDR ranges allowed to access the API (empty list = allow all - NOT RECOMMENDED)"
  type        = list(string)
}

variable "enable_firestore" {
  description = "Enable Firestore for metadata storage (if false, uses in-memory only)"
  type        = bool
  default     = true
}

# LAB MODE TOGGLES - DO NOT USE OUTSIDE LAB ENVIRONMENT
# These introduce intentional security vulnerabilities for training purposes

variable "lab_mode_skip_object_ownership_check" {
  description = "LAB ONLY: Skip ownership verification for image access (enables IDOR vulnerability)"
  type        = bool
  default     = false

  validation {
    condition     = !var.lab_mode_skip_object_ownership_check || var.environment == "lab"
    error_message = "lab_mode_skip_object_ownership_check can only be enabled when environment = 'lab'"
  }
}

variable "lab_mode_weak_token_validation" {
  description = "LAB ONLY: Weaken JWT validation (enables token bypass vulnerability)"
  type        = bool
  default     = false

  validation {
    condition     = !var.lab_mode_weak_token_validation || var.environment == "lab"
    error_message = "lab_mode_weak_token_validation can only be enabled when environment = 'lab'"
  }
}

variable "bucket_name" {
  description = "Name for the Cloud Storage bucket (must be globally unique)"
  type        = string
}

