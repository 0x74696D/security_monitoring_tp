# -----------------------------------------------------------------------------
# VPC Network
# -----------------------------------------------------------------------------
resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# -----------------------------------------------------------------------------
# Subnet
# -----------------------------------------------------------------------------
resource "google_compute_subnetwork" "subnet" {
  name          = "${var.network_name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.vpc.id

  # Enable VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# -----------------------------------------------------------------------------
# Cloud Router (required for Cloud NAT)
# -----------------------------------------------------------------------------
resource "google_compute_router" "router" {
  name    = "${var.network_name}-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

# -----------------------------------------------------------------------------
# Cloud NAT (provides outbound internet access for private VMs)
# -----------------------------------------------------------------------------
resource "google_compute_router_nat" "nat" {
  name                               = "${var.network_name}-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# -----------------------------------------------------------------------------
# Firewall Rules
# -----------------------------------------------------------------------------

# Allow SSH from anywhere
resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.network_name}-allow-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["allow-ssh"]
}

# Allow port 8080 from anywhere
resource "google_compute_firewall" "allow_8080" {
  name    = "${var.network_name}-allow-8080"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["allow-8080"]
}

# Allow SSH from IAP IP range for private VM
resource "google_compute_firewall" "allow_ssh_iap" {
  name    = "${var.network_name}-allow-ssh-iap"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["allow-ssh-iap"]
}

# -----------------------------------------------------------------------------
# Compute Instance (VM)
# -----------------------------------------------------------------------------
resource "google_compute_instance" "vm" {
  name         = "target-vm"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["allow-ssh", "allow-8080"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id

    # Ephemeral external IP for internet access
    access_config {}
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  # Allow stopping for updates
  allow_stopping_for_update = true
}

# -----------------------------------------------------------------------------
# Private Compute Instance (VM) - No Internet Access
# -----------------------------------------------------------------------------
resource "google_compute_instance" "vm_private" {
  name         = "attacker-vm"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["allow-ssh-iap"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 10
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.subnet.id

    # No access_config block = No external IP = Not exposed to internet
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  # Allow stopping for updates
  allow_stopping_for_update = true
}

# -----------------------------------------------------------------------------
# Enable Audit Logs Configuration
# -----------------------------------------------------------------------------
resource "google_project_iam_audit_config" "audit_logs" {
  project = var.project_id
  service = "allServices"
  
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  
  audit_log_config {
    log_type = "DATA_READ"
  }
  
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# -----------------------------------------------------------------------------
# BigQuery Dataset for VPC Flow Logs and Audit Logs
# -----------------------------------------------------------------------------
resource "google_bigquery_dataset" "vpc_flow_logs" {
  dataset_id    = "vpc_flow_and_audit_logs"
  friendly_name = "VPC Flow and Audit Logs"
  description   = "BigQuery dataset for VPC flow logs and audit logs (Admin Activity, Data Access, Policy Denied)"
  location      = var.region
  
  # Allow deletion even if dataset contains tables
  delete_contents_on_destroy = true
  
  # Delete logs older than 30 days
  default_table_expiration_ms = 2592000000  # 30 days in milliseconds
  
  labels = {
    environment = "production"
    type        = "logs"
  }
}

# -----------------------------------------------------------------------------
# Log Sink for VPC Flow Logs and Audit Logs
# -----------------------------------------------------------------------------
resource "google_logging_project_sink" "vpc_flow_logs_sink" {
  name        = "vpc-flow-audit-logs-sink"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.vpc_flow_logs.dataset_id}"
  
  # Filter to capture VPC flow logs and audit logs (Admin Activity, Data Access, Policy Denied)
  filter = <<-EOT
    resource.type="gce_subnetwork"
    OR
    LOG_ID("cloudaudit.googleapis.com/activity")
    OR
    LOG_ID("cloudaudit.googleapis.com/data_access")
    OR
    LOG_ID("cloudaudit.googleapis.com/policy")
  EOT
  
  # Use unique writer identity
  unique_writer_identity = true
}

# Grant the log sink writer permission to write to BigQuery
resource "google_bigquery_dataset_iam_member" "vpc_flow_logs_writer" {
  dataset_id = google_bigquery_dataset.vpc_flow_logs.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.vpc_flow_logs_sink.writer_identity
}

