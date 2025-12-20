# Project and Region Configuration
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

# Network Configuration
variable "use_default_vpc" {
  description = "Use default VPC instead of creating a new one"
  type        = bool
  default     = false
}

variable "network_name" {
  description = "Name of the VPC network (if creating new)"
  type        = string
  default     = "wazuh-vpc"
}

variable "subnet_name" {
  description = "Name of the subnet"
  type        = string
  default     = "wazuh-subnet"
}

variable "subnet_cidr" {
  description = "CIDR range for the subnet"
  type        = string
  default     = "10.0.1.0/24"
}

# Firewall Configuration
variable "allowed_ssh_cidr" {
  description = "CIDR range allowed to SSH to the VM (e.g., your public IP/32)"
  type        = string
  default     = "0.0.0.0/0" # CHANGE THIS TO YOUR IP/32 for production
}

# Compute Instance Configuration
variable "instance_name" {
  description = "Name of the compute instance"
  type        = string
  default     = "wazuh-aio"
}

variable "machine_type" {
  description = "Machine type for the compute instance"
  type        = string
  default     = "e2-standard-4"
}

variable "boot_disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 100
}

variable "boot_disk_type" {
  description = "Boot disk type"
  type        = string
  default     = "pd-standard"
}

variable "os_image" {
  description = "OS image for the compute instance"
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2204-lts"
}

variable "enable_os_login" {
  description = "Enable OS Login for the instance"
  type        = bool
  default     = false
}

# Wazuh Configuration
variable "wazuh_admin_password" {
  description = "Admin password for Wazuh dashboard (min 8 characters)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.wazuh_admin_password) >= 8
    error_message = "Admin password must be at least 8 characters long."
  }
}

variable "wazuh_version" {
  description = "Wazuh version to deploy"
  type        = string
  default     = "4.14.1"
}

# Secret Manager Configuration
variable "use_secret_manager" {
  description = "Store admin password in Secret Manager instead of passing directly"
  type        = bool
  default     = false
}

variable "secret_name" {
  description = "Secret Manager secret name for admin password"
  type        = string
  default     = "wazuh-admin-password"
}

# Cloud Logging Export Configuration
variable "enable_log_export" {
  description = "Enable Cloud Logging export to Pub/Sub"
  type        = bool
  default     = true
}

variable "pubsub_topic_name" {
  description = "Pub/Sub topic name for log export"
  type        = string
  default     = "wazuh-logs"
}

# Labels
variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default = {
    env         = "lab"
    app         = "wazuh"
    managed_by  = "terraform"
  }
}

