# VPC Network
resource "google_compute_network" "wazuh_vpc" {
  count                            = var.use_default_vpc ? 0 : 1
  name                             = var.network_name
  auto_create_subnetworks          = false
  enable_ula_internal_ipv6         = true
  internal_ipv6_range              = null
  project                          = var.project_id
}

# Subnet
resource "google_compute_subnetwork" "wazuh_subnet" {
  count                    = var.use_default_vpc ? 0 : 1
  name                     = var.subnet_name
  ip_cidr_range            = var.subnet_cidr
  region                   = var.region
  network                  = google_compute_network.wazuh_vpc[0].id
  project                  = var.project_id
  stack_type               = "IPV4_IPV6"
  ipv6_access_type         = "EXTERNAL"

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Firewall Rule: Allow SSH from specified CIDR (IPv4)
resource "google_compute_firewall" "allow_ssh_ipv4" {
  name    = "${var.network_name}-allow-ssh-ipv4"
  network = var.use_default_vpc ? "default" : google_compute_network.wazuh_vpc[0].name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_cidr_ipv4
  target_tags   = ["wazuh-ssh"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Firewall Rule: Allow SSH from specified CIDR (IPv6)
resource "google_compute_firewall" "allow_ssh_ipv6" {
  count   = length(var.allowed_ssh_cidr_ipv6) > 0 ? 1 : 0
  name    = "${var.network_name}-allow-ssh-ipv6"
  network = var.use_default_vpc ? "default" : google_compute_network.wazuh_vpc[0].name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.allowed_ssh_cidr_ipv6
  target_tags   = ["wazuh-ssh"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Firewall Rule: Allow internal communication 
resource "google_compute_firewall" "allow_internal" {
  count   = var.use_default_vpc ? 0 : 1
  name    = "${var.network_name}-allow-internal"
  network = google_compute_network.wazuh_vpc[0].name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.subnet_cidr]
}

# Firewall Rule: Allow egress (IPv4)
resource "google_compute_firewall" "allow_egress_ipv4" {
  name      = "${var.network_name}-allow-egress-ipv4"
  network   = var.use_default_vpc ? "default" : google_compute_network.wazuh_vpc[0].name
  project   = var.project_id
  direction = "EGRESS"

  allow {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
}

# Firewall Rule: Allow egress (IPv6)
resource "google_compute_firewall" "allow_egress_ipv6" {
  count     = var.use_default_vpc ? 0 : 1
  name      = "${var.network_name}-allow-egress-ipv6"
  network   = google_compute_network.wazuh_vpc[0].name
  project   = var.project_id
  direction = "EGRESS"

  allow {
    protocol = "all"
  }

  destination_ranges = ["::/0"]
}

# Service Account for Wazuh VM
resource "google_service_account" "wazuh_sa" {
  account_id   = "wazuh-vm-sa"
  display_name = "Wazuh VM Service Account"
  project      = var.project_id
}

# IAM: Grant logging write permissions
resource "google_project_iam_member" "wazuh_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.wazuh_sa.email}"
}

# IAM: Grant monitoring metric writer permissions
resource "google_project_iam_member" "wazuh_monitoring" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.wazuh_sa.email}"
}

# IAM: Grant Secret Manager accessor (if using Secret Manager)
resource "google_project_iam_member" "wazuh_secret_accessor" {
  count   = var.use_secret_manager ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.wazuh_sa.email}"
}

# Secret Manager: Create secret for admin password (if enabled)
resource "google_secret_manager_secret" "wazuh_admin_password" {
  count     = var.use_secret_manager ? 1 : 0
  secret_id = var.secret_name
  project   = var.project_id

  replication {
    auto {}
  }

  labels = var.labels
}

# Secret Manager: Store admin password version
resource "google_secret_manager_secret_version" "wazuh_admin_password_version" {
  count       = var.use_secret_manager ? 1 : 0
  secret      = google_secret_manager_secret.wazuh_admin_password[0].id
  secret_data = var.wazuh_admin_password
}

# IAM: Grant Pub/Sub subscriber permissions for GCP integration
resource "google_project_iam_member" "wazuh_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.wazuh_sa.email}"
}

# Compute Instance: Wazuh All-in-One
resource "google_compute_instance" "wazuh_vm" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone
  project      = var.project_id

  tags = ["wazuh-ssh", "wazuh-vm"]

  boot_disk {
    initialize_params {
      image = var.os_image
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network    = var.use_default_vpc ? "default" : google_compute_network.wazuh_vpc[0].name
    subnetwork = var.use_default_vpc ? null : google_compute_subnetwork.wazuh_subnet[0].name
    stack_type = var.use_default_vpc ? null : "IPV4_IPV6"

    # Assign external IPv4 for SSH access
    access_config {
      # Ephemeral IPv4
    }

    # Assign external IPv6 for SSH access
    dynamic "ipv6_access_config" {
      for_each = var.use_default_vpc ? [] : [1]
      content {
        network_tier = "PREMIUM"
      }
    }
  }

  service_account {
    email  = google_service_account.wazuh_sa.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = var.enable_os_login ? "TRUE" : "FALSE"
    gcp-sa-key     = file(var.gcp_service_account_key_path)
  }

  metadata_startup_script = templatefile("${path.module}/install.sh", {
    use_secret_manager     = var.use_secret_manager
    secret_name            = var.secret_name
    project_id             = var.project_id
    admin_password         = var.wazuh_admin_password
    wazuh_version          = var.wazuh_version
    gcp_sa_key_path        = var.gcp_service_account_key_path
    pubsub_project_id      = var.pubsub_project_id
    pubsub_subscription_id = var.pubsub_subscription_id
  })

  labels = var.labels

  # Allow stopping for updates
  allow_stopping_for_update = true

  # Depends on firewall rules and service account IAM
  depends_on = [
    google_compute_firewall.allow_ssh_ipv4,
    google_compute_firewall.allow_ssh_ipv6,
    google_project_iam_member.wazuh_logging,
    google_project_iam_member.wazuh_monitoring,
    google_project_iam_member.wazuh_secret_accessor,
  ]
}
