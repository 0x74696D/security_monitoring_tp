variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "bounc-473410"
}

variable "region" {
  description = "The GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP zone for the cluster"
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "The name of the GKE cluster"
  type        = string
  default     = "lab-test-cluster"
}

variable "machine_type" {
  description = "Machine type for the node pool"
  type        = string
  default     = "e2-small"
}

variable "node_count" {
  description = "Number of nodes in the node pool"
  type        = number
  default     = 1
}

