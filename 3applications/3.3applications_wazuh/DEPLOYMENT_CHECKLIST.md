# Wazuh + GCP Pub/Sub Deployment Checklist

## Pre-Deployment Requirements

### ✅ GCP Prerequisites
- [ ] GCP Project created: `telecom-3app`
- [ ] Log Sink created and publishing to Pub/Sub
- [ ] Pub/Sub topic: `wazuh-gcp-logs`
- [ ] Pub/Sub subscription: `wazuh-gcp-logs-sub`
- [ ] Service account key downloaded: `~/wazuh.json`
- [ ] Service account has Pub/Sub Subscriber role

### ✅ Terraform Variables
- [ ] `terraform.tfvars` updated with:
  - `gcp_service_account_key_path = "~/wazuh.json"`
  - `pubsub_project_id = "telecom-3app"`
  - `pubsub_subscription_id = "wazuh-gcp-logs-sub"`
  - `wazuh_admin_password = "YourSecurePassword"`
  - `allowed_ssh_cidr_ipv4` or `allowed_ssh_cidr_ipv6`

## Deployment Steps

### 1. Deploy Infrastructure
```bash
cd /Users/tim.mannai/telecomparis/3applications
terraform init
terraform plan
terraform apply
```

**Expected Time:** ~5-7 minutes

### 2. Wait for Installation
The startup script installs:
- Docker & Docker Compose
- Wazuh (single-node)
- GCP Pub/Sub integration (command wodle)
- Custom rules and configurations

**Expected Time:** ~5 minutes

### 3. Monitor Installation Progress
```bash
# SSH to VM
gcloud compute ssh wazuh-aio --zone=us-central1-a --project=telecom-3app

# Watch installation log
sudo tail -f /var/log/wazuh-install.log
```

Look for:
- ✅ "Wazuh containers are ready"
- ✅ "GCP service account key configured"
- ✅ "GCP Pub/Sub command wodle configured successfully"
- ✅ "GCP Pub/Sub connection successful"
- ✅ "Wazuh Installation Complete!"

## Verification Steps

### 4. Verify Docker Containers
```bash
sudo docker ps
```
**Expected:** 3 containers running (manager, indexer, dashboard)

### 5. Verify GCP Command Wodle
```bash
sudo docker exec single-node-wazuh.manager-1 grep 'command:gcp' /var/ossec/logs/ossec.log
```
**Expected:** Lines showing "Starting command 'gcp'" every minute

### 6. Test GCP Connection
```bash
sudo docker exec single-node-wazuh.manager-1 /var/ossec/wodles/gcloud/gcloud \
  -T pubsub -p telecom-3app -s wazuh-gcp-logs-sub \
  -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 2 -l 1
```
**Expected:** "Received and acknowledged X messages"

### 7. Check GCP Alerts
```bash
# In Wazuh logs
sudo docker exec single-node-wazuh.manager-1 grep '"integration":"gcp"' /var/ossec/logs/alerts/alerts.json | wc -l
```
**Expected:** > 0 (number of GCP alerts)

### 8. Verify Elasticsearch Indexing
```bash
curl -k -u admin:YourPassword 'https://localhost:9200/wazuh-alerts-*/_count?q=integration:gcp'
```
**Expected:** `{"count": N, ...}` where N > 0

## Dashboard Access

### 9. Create SSH Tunnel
```bash
# From your local machine
gcloud compute ssh wazuh-aio --zone=us-central1-a --project=telecom-3app -- -L 5601:localhost:5601
```

### 10. Access Dashboard
- **URL:** http://localhost:5601
- **Username:** admin
- **Password:** (from terraform.tfvars)

### 11. Search for GCP Logs
In the dashboard:
1. Go to "Discover" or "Security Events"
2. Search: `rule.groups:gcp` OR `integration:gcp`
3. Select time range (e.g., Last 24 hours)

**Expected:** GCP logs visible with fields like:
- `integration: gcp`
- `gcp.resource.type`: cloud_run_revision, api, gce_instance, etc.
- `gcp.severity`: INFO, WARNING, ERROR, etc.
- `gcp.protoPayload.methodName`: API methods

## Troubleshooting

### No GCP alerts?
```bash
# 1. Check wodle is configured
sudo docker exec single-node-wazuh.manager-1 grep -A10 "GCP Pub/Sub Integration" /var/ossec/etc/ossec.conf

# 2. Check for errors
sudo docker exec single-node-wazuh.manager-1 grep -i "error\|fail" /var/ossec/logs/ossec.log | grep -i gcp

# 3. Restart Wazuh
sudo docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

# 4. Restart Filebeat
sudo docker exec single-node-wazuh.manager-1 pkill filebeat
```

### Pub/Sub subscription empty?
```bash
# Check if logs are flowing to Pub/Sub
gcloud pubsub subscriptions pull wazuh-gcp-logs-sub --limit=1 --project=telecom-3app
```

### Dashboard not accessible?
```bash
# Check dashboard container
sudo docker ps | grep dashboard

# Check dashboard logs
sudo docker logs single-node-wazuh.dashboard-1

# Verify port
sudo netstat -tlnp | grep 5601
```

## Success Criteria

✅ **Deployment Successful When:**
- [ ] All Docker containers running
- [ ] GCP command wodle executing every minute
- [ ] GCP alerts in alerts.json
- [ ] GCP alerts in Elasticsearch (count > 0)
- [ ] Dashboard accessible
- [ ] GCP logs visible in dashboard with filter `rule.groups:gcp`

## Cleanup

### Remove Deployment
```bash
terraform destroy
```

**Note:** This will delete:
- Wazuh VM
- Static IP
- Firewall rules
- Service account bindings

**Will NOT delete:**
- Pub/Sub topic/subscription
- Log sink
- Service account key

## Support & Documentation

- **Wazuh Docs:** https://documentation.wazuh.com/
- **GCP Integration:** See `GCP_INTEGRATION_NOTES.md`
- **Terraform Outputs:** Run `terraform output` for connection details
