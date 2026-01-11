# GKE Cluster
resource "google_container_cluster" "primary" {
  name     = var.cluster_name
  location = var.zone

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = false

  # Minimal cluster configuration
  network    = "default"
  subnetwork = "default"

  # Enable Workload Identity (recommended)
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Disable legacy ABAC
  enable_legacy_abac = false

  # Release channel for automatic upgrades
  release_channel {
    channel = "REGULAR"
  }

  # Enable comprehensive logging
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  # Enable comprehensive monitoring
  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }
}

# Separately Managed Node Pool
resource "google_container_node_pool" "primary_nodes" {
  name       = "${var.cluster_name}-node-pool"
  location   = var.zone
  cluster    = google_container_cluster.primary.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 20
    disk_type    = "pd-standard"

    # Google recommends custom service accounts with minimum permissions
    # Using default compute service account for simplicity
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    # Enable Workload Identity on nodes
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

