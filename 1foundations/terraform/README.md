# GCP Security Lab - Terraform Infrastructure Exercise

## 📚 Overview

This lab creates a GCP infrastructure for security analysis and network monitoring exercises. You'll deploy VMs, configure VPC networks, enable flow logs, and analyze traffic patterns using BigQuery.

## 🎯 Learning Objectives

By completing these exercises, you will:
- Deploy infrastructure as code using Terraform
- Configure VPC networks with custom firewall rules
- Enable and analyze VPC flow logs
- Query audit logs in BigQuery
- Detect port scanning activity
- Understand Cloud NAT for private VM internet access

---

## 🏗️ Infrastructure Architecture

```
┌─────────────────────────────────────────────────────┐
│                 VPC: simple-vpc                     │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  Subnet: 10.0.1.0/24 (us-central1)          │  │
│  │                                              │  │
│  │  ┌─────────────┐      ┌─────────────┐       │  │
│  │  │  target-vm  │      │ attacker-vm │       │  │
│  │  │  10.0.1.4   │      │  10.0.1.3   │       │  │
│  │  │ (Public IP) │      │ (No Pub IP) │       │  │
│  │  └─────────────┘      └─────────────┘       │  │
│  │       │                      │               │  │
│  │       │                      │               │  │
│  │    Firewall:              Firewall:          │  │
│  │   - SSH (22)            - SSH via IAP        │  │
│  │   - HTTP (8080)         (35.235.240.0/20)    │  │
│  │                                              │  │
│  └──────────────────────────────────────────────┘  │
│                      │                             │
│                      │                             │
│              ┌───────┴────────┐                    │
│              │   Cloud NAT    │                    │
│              │   Cloud Router │                    │
│              └────────────────┘                    │
│                      │                             │
└──────────────────────┼─────────────────────────────┘
                       │
                   Internet
                       │
              ┌────────┴────────┐
              │  BigQuery       │
              │  Dataset:       │
              │  vpc_flow_and_  │
              │  audit_logs     │
              └─────────────────┘
```

---

## 📋 Prerequisites

- Google Cloud Platform account
- `gcloud` CLI installed and configured
- `terraform` installed (>= 1.0.0)
- `bq` command-line tool (comes with gcloud)
- GCP Project with billing enabled

---

## 🚀 Exercise 1: Setup and Authentication

### Step 1.1: Authenticate with GCP

```bash
# Login to gcloud
gcloud auth login

# Set your project
gcloud config set project bounc-473410

# Setup application default credentials for Terraform
gcloud auth application-default login --account=bounc.siem@gmail.com
```

### Step 1.2: Enable Required APIs

```bash
# Enable Compute Engine API
gcloud services enable compute.googleapis.com

# Enable BigQuery API
gcloud services enable bigquery.googleapis.com

# Enable Cloud Logging API
gcloud services enable logging.googleapis.com

# Enable IAP API (for SSH tunneling)
gcloud services enable iap.googleapis.com
```

**✅ Checkpoint:** Run `gcloud services list --enabled` and verify all APIs are enabled.

---

## 🔧 Exercise 2: Deploy Infrastructure with Terraform

### Step 2.1: Review Terraform Files

Before deploying, understand what each file does:

| File | Purpose |
|------|---------|
| `versions.tf` | Defines Terraform and provider versions |
| `provider.tf` | Configures GCP provider |
| `variables.tf` | Defines input variables |
| `main.tf` | Contains all resource definitions |
| `outputs.tf` | Defines output values after deployment |

**Task:** Open `main.tf` and identify the following resources:
- VPC Network
- Subnet
- Firewall Rules (how many?)
- Compute Instances (how many?)
- Cloud NAT
- BigQuery Dataset
- Log Sink

<details>
<summary>💡 Answer</summary>

Resources in `main.tf`:
1. VPC Network: `google_compute_network.vpc`
2. Subnet: `google_compute_subnetwork.subnet`
3. Firewall Rules: 3 rules
   - `allow_ssh` (port 22 from anywhere)
   - `allow_8080` (port 8080 from anywhere)
   - `allow_ssh_iap` (port 22 from IAP range)
4. Compute Instances: 2 VMs
   - `target-vm` (public)
   - `attacker-vm` (private)
5. Cloud NAT: `google_compute_router_nat.nat`
6. BigQuery Dataset: `google_bigquery_dataset.vpc_flow_logs`
7. Log Sink: `google_logging_project_sink.vpc_flow_logs_sink`
</details>

### Step 2.2: Initialize Terraform

```bash
cd /Users/tim.mannai/telecomparis/1foundations/terraform

# Initialize Terraform (downloads providers)
TMPDIR=/tmp terraform init
```

**Expected Output:** 
```
Terraform has been successfully initialized!
```

### Step 2.3: Review the Plan

```bash
# Generate and review execution plan
TMPDIR=/tmp terraform plan
```

**Task:** Answer these questions:
1. How many resources will be created?
2. What will be the external IP assignment for each VM?
3. Which firewall rule allows internet access to port 8080?

### Step 2.4: Apply the Configuration

```bash
# Deploy the infrastructure
TMPDIR=/tmp terraform apply

# Review the plan and type 'yes' to confirm
```

**⏱️ Expected Duration:** 2-3 minutes

### Step 2.5: Verify Outputs

```bash
# View all outputs
TMPDIR=/tmp terraform output

# Get specific values
terraform output vm_external_ip
terraform output vm_private_internal_ip
```

**✅ Checkpoint:** You should see:
- External IP for `target-vm`
- Internal IPs for both VMs
- BigQuery dataset name
- SSH commands

---

## 🌐 Exercise 3: Network Connectivity Testing

### Step 3.1: SSH to Public VM (target-vm)

```bash
# Get the SSH command from outputs
terraform output ssh_command

# Or manually:
gcloud compute ssh target-vm --zone=us-central1-a --project=bounc-473410
```

**Inside the VM, run:**
```bash
# Check internet connectivity
ping -c 3 8.8.8.8

# Check internal IP
ip addr show

# Exit VM
exit
```

### Step 3.2: SSH to Private VM (attacker-vm)

```bash
# This VM has NO public IP, must use IAP tunnel
gcloud compute ssh attacker-vm \
  --zone=us-central1-a \
  --project=bounc-473410 \
  --tunnel-through-iap
```

**Inside the VM, run:**
```bash
# Check internet connectivity (through Cloud NAT)
ping -c 3 8.8.8.8

# Install tools for security testing
sudo apt update
sudo apt install -y nmap netcat-traditional curl

# Exit VM
exit
```

**Task:** Explain why `attacker-vm` can access the internet despite having no public IP.

<details>
<summary>💡 Answer</summary>

The `attacker-vm` can access the internet through **Cloud NAT** (Network Address Translation). Cloud NAT allows private VMs to initiate outbound connections to the internet while preventing inbound connections from the internet, maintaining security.
</details>

---

## 🔍 Exercise 4: VPC Flow Logs Analysis

### Step 4.1: Generate Network Traffic

Let's generate some traffic to populate the flow logs:

```bash
# From your local machine, test the public VM
EXTERNAL_IP=$(terraform output -raw vm_external_ip)

# Test SSH (should work)
ssh -o ConnectTimeout=5 $EXTERNAL_IP echo "SSH works"

# Test port 8080 (no service running, but traffic is logged)
curl -m 5 http://$EXTERNAL_IP:8080 || echo "Connection attempted"

# Test a closed port (should fail, but gets logged)
nc -zv -w 5 $EXTERNAL_IP 9999 || echo "Port scan logged"
```

### Step 4.2: Wait for Logs

**⏱️ Important:** VPC flow logs can take **5-10 minutes** to appear in BigQuery.

```bash
# Check if logs are flowing to Cloud Logging
gcloud logging read 'resource.type="gce_subnetwork"' \
  --limit=5 \
  --project=bounc-473410 \
  --format="table(timestamp,jsonPayload.connection.src_ip,jsonPayload.connection.dest_port)"
```

### Step 4.3: Verify BigQuery Tables

```bash
# List tables in the dataset
bq ls --project_id=bounc-473410 vpc_flow_and_audit_logs
```

**Expected Tables:**
- `compute_googleapis_com_vpc_flows_YYYYMMDD`
- `cloudaudit_googleapis_com_activity_YYYYMMDD`
- `cloudaudit_googleapis_com_data_access_YYYYMMDD`

### Step 4.4: Query VPC Flow Logs

**Query 1: Last 10 network flows**

```sql
SELECT
  timestamp,
  jsonPayload.connection.src_ip,
  jsonPayload.connection.dest_ip,
  jsonPayload.connection.dest_port,
  jsonPayload.bytes_sent
FROM
  `bounc-473410.vpc_flow_and_audit_logs.compute_googleapis_com_vpc_flows_*`
WHERE
  resource.type = "gce_subnetwork"
ORDER BY
  timestamp DESC
LIMIT 10;
```

**Query 2: Traffic summary by port**

```sql
SELECT
  CAST(jsonPayload.connection.dest_port AS INT64) AS port,
  COUNT(*) AS connection_count,
  SUM(jsonPayload.bytes_sent) AS total_bytes
FROM
  `bounc-473410.vpc_flow_and_audit_logs.compute_googleapis_com_vpc_flows_*`
WHERE
  resource.type = "gce_subnetwork"
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY
  port
ORDER BY
  connection_count DESC;
```

**✅ Checkpoint:** You should see traffic on ports 22, 8080, and any other ports you tested.

---

## 🛡️ Exercise 5: Simulate and Detect Port Scanning

### Step 5.1: Perform Port Scan from attacker-vm

```bash
# SSH to attacker-vm
gcloud compute ssh attacker-vm \
  --zone=us-central1-a \
  --project=bounc-473410 \
  --tunnel-through-iap
```

**Inside attacker-vm:**
```bash
# Get target-vm IP
TARGET_IP="10.0.1.4"

# Perform a simple port scan (first 100 ports)
nmap -p 1-100 $TARGET_IP

# Perform a more aggressive scan
nmap -p 1-1000 -T4 $TARGET_IP

# Exit
exit
```

### Step 5.2: Wait and Query for Port Scanning Activity

**⏱️ Wait 5-10 minutes** for logs to reach BigQuery.

**Port Scanning Detection Query:**

```sql
SELECT
  jsonPayload.connection.src_ip AS scanner_ip,
  jsonPayload.connection.dest_ip AS target_ip,
  COUNT(DISTINCT CAST(jsonPayload.connection.dest_port AS INT64)) AS unique_ports_targeted,
  MIN(timestamp) AS scan_start_time,
  MAX(timestamp) AS scan_end_time,
  TIMESTAMP_DIFF(MAX(timestamp), MIN(timestamp), SECOND) AS scan_duration_seconds,
  COUNT(*) AS total_connection_attempts
FROM
  `bounc-473410.vpc_flow_and_audit_logs.compute_googleapis_com_vpc_flows_*`
WHERE
  resource.type = "gce_subnetwork"
  AND jsonPayload.connection.dest_port IS NOT NULL
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY
  scanner_ip,
  target_ip
HAVING
  unique_ports_targeted >= 10  -- Threshold for port scanning
ORDER BY
  unique_ports_targeted DESC;
```

**Task:** 
1. Run the query above
2. Identify the IP addresses involved
3. How many unique ports were scanned?
4. How long did the scan take?

### Step 5.3: Advanced Detection - Identify Scan Pattern

```sql
-- Show which ports were scanned
SELECT
  jsonPayload.connection.src_ip AS scanner_ip,
  jsonPayload.connection.dest_ip AS target_ip,
  CAST(jsonPayload.connection.dest_port AS INT64) AS port_scanned,
  COUNT(*) AS scan_attempts,
  MIN(timestamp) AS first_attempt,
  MAX(timestamp) AS last_attempt
FROM
  `bounc-473410.vpc_flow_and_audit_logs.compute_googleapis_com_vpc_flows_*`
WHERE
  resource.type = "gce_subnetwork"
  AND jsonPayload.connection.src_ip = "10.0.1.3"  -- attacker-vm IP
  AND jsonPayload.connection.dest_ip = "10.0.1.4"  -- target-vm IP
  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY
  scanner_ip,
  target_ip,
  port_scanned
ORDER BY
  port_scanned ASC;
```

---

## 📊 Exercise 6: Audit Logs Analysis

### Step 6.1: View Admin Activity Logs

**Query: Recent administrative actions**

```sql
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail AS who,
  protoPayload.methodName AS what,
  protoPayload.resourceName AS resource,
  severity
FROM
  `bounc-473410.vpc_flow_and_audit_logs.cloudaudit_googleapis_com_activity_*`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
ORDER BY
  timestamp DESC
LIMIT 20;
```

**Task:** 
1. Who created the VMs?
2. What method was used to create the network?
3. When were the firewall rules created?

### Step 6.2: View Data Access Logs

**Query: API calls and data access**

```sql
SELECT
  timestamp,
  protoPayload.authenticationInfo.principalEmail AS user,
  protoPayload.methodName AS api_method,
  protoPayload.serviceName AS service,
  COUNT(*) AS call_count
FROM
  `bounc-473410.vpc_flow_and_audit_logs.cloudaudit_googleapis_com_data_access_*`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
GROUP BY
  timestamp,
  user,
  api_method,
  service
ORDER BY
  timestamp DESC
LIMIT 20;
```

---

## 🧹 Exercise 7: Cleanup Resources

### Step 7.1: Review Resources to be Destroyed

```bash
# Show what will be destroyed
TMPDIR=/tmp terraform plan -destroy
```

### Step 7.2: Destroy Infrastructure

```bash
# Destroy all resources
TMPDIR=/tmp terraform destroy

# Type 'yes' to confirm
```

**⏱️ Expected Duration:** 3-5 minutes

**Note:** The BigQuery dataset might need manual deletion if it contains data:

```bash
# Force delete dataset with all tables
bq rm -r -f -d bounc-473410:vpc_flow_and_audit_logs
```

---

## 📝 Key Concepts Summary

### Terraform Resources Created

| Resource Type | Resource Name | Purpose |
|---------------|---------------|---------|
| VPC Network | `simple-vpc` | Isolated network environment |
| Subnet | `simple-vpc-subnet` | IP range 10.0.1.0/24 |
| Firewall Rule | `allow_ssh` | SSH access from internet |
| Firewall Rule | `allow_8080` | HTTP access on port 8080 |
| Firewall Rule | `allow_ssh_iap` | SSH via IAP for private VM |
| VM Instance | `target-vm` | Public VM with external IP |
| VM Instance | `attacker-vm` | Private VM (no external IP) |
| Cloud Router | `simple-vpc-router` | Required for Cloud NAT |
| Cloud NAT | `simple-vpc-nat` | Outbound internet for private VMs |
| BigQuery Dataset | `vpc_flow_and_audit_logs` | Stores all logs |
| Log Sink | `vpc-flow-audit-logs-sink` | Routes logs to BigQuery |
| Audit Config | Project-level | Enables audit logging |

### Security Concepts

1. **VPC Flow Logs**: Capture network traffic metadata (IPs, ports, protocols)
2. **Cloud Audit Logs**: Track API calls and administrative actions
3. **Cloud NAT**: Allows private VMs to access internet without public IPs
4. **IAP (Identity-Aware Proxy)**: Secure SSH access without public IPs
5. **Port Scanning Detection**: Identify reconnaissance activities
6. **Firewall Rules**: Control network access with tags

---

## 🔧 Troubleshooting

### Issue: Terraform Init Fails with Permission Denied

**Solution:**
```bash
export TMPDIR=/tmp
terraform init
```

### Issue: No Logs in BigQuery

**Checklist:**
1. Wait 5-10 minutes after generating traffic
2. Verify sink exists: `gcloud logging sinks list --project=bounc-473410`
3. Check log filter is correct
4. Generate more traffic to ensure logs are created
5. Verify IAM permissions on BigQuery dataset

**Debug Commands:**
```bash
# Check if logs exist in Cloud Logging
gcloud logging read 'resource.type="gce_subnetwork"' --limit=5 --project=bounc-473410

# List BigQuery tables
bq ls --project_id=bounc-473410 vpc_flow_and_audit_logs

# Check sink configuration
gcloud logging sinks describe vpc-flow-audit-logs-sink --project=bounc-473410
```

### Issue: Cannot SSH to Private VM

**Solution:** Make sure you're using IAP tunnel:
```bash
gcloud compute ssh attacker-vm \
  --zone=us-central1-a \
  --project=bounc-473410 \
  --tunnel-through-iap
```

If it fails, check:
1. IAP API is enabled: `gcloud services enable iap.googleapis.com`
2. Firewall rule `allow_ssh_iap` exists and uses correct source range `35.235.240.0/20`

---

## 📚 Additional Resources

- [Terraform GCP Provider Documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [VPC Flow Logs Documentation](https://cloud.google.com/vpc/docs/flow-logs)
- [Cloud Audit Logs Overview](https://cloud.google.com/logging/docs/audit)
- [BigQuery Documentation](https://cloud.google.com/bigquery/docs)
- [Cloud NAT Overview](https://cloud.google.com/nat/docs/overview)

---

## 🎓 Challenge Questions

1. **Network Security**: How would you modify the firewall rules to allow SSH only from your IP address?

2. **Cost Optimization**: VPC Flow Logs can be expensive at scale. How would you reduce costs while maintaining security visibility?

3. **Advanced Detection**: Write a BigQuery query to detect:
   - Brute force SSH attempts (multiple connections to port 22 from same IP)
   - Data exfiltration (large amounts of data sent to external IPs)

4. **Architecture**: Why is it better to have `attacker-vm` without a public IP? What security benefits does this provide?

5. **Compliance**: Which audit logs would help you comply with regulations like GDPR or SOC 2?

---

## ✅ Exercise Completion Checklist

- [ ] Authenticated with GCP
- [ ] Enabled required APIs
- [ ] Reviewed Terraform configuration files
- [ ] Deployed infrastructure with `terraform apply`
- [ ] Connected to both VMs via SSH
- [ ] Generated network traffic
- [ ] Verified logs in BigQuery
- [ ] Performed port scanning simulation
- [ ] Detected port scanning in BigQuery
- [ ] Analyzed audit logs
- [ ] Cleaned up resources with `terraform destroy`

**Congratulations! 🎉** You've completed the GCP Security Lab exercises!

