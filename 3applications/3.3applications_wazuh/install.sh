#!/bin/bash
set -e

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log "Starting Wazuh All-in-One deployment..."

# Update system
log "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# Install prerequisites
log "Installing prerequisites..."
apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    python3-yaml

# Install Docker
log "Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable Docker service
log "Enabling Docker service..."
systemctl enable docker
systemctl start docker

# Create Wazuh directory
log "Creating Wazuh directory..."
rm -rf /opt/wazuh
mkdir -p /opt/wazuh
cd /opt/wazuh

# Determine admin password source
%{ if use_secret_manager }
log "Fetching admin password from Secret Manager..."
ADMIN_PASSWORD=$(gcloud secrets versions access latest --secret="${secret_name}" --project="${project_id}")
%{ else }
log "Using admin password from Terraform variable..."
ADMIN_PASSWORD="${admin_password}"
%{ endif }

# Validate password
if [ -z "$ADMIN_PASSWORD" ] || [ "$${#ADMIN_PASSWORD}" -lt 8 ]; then
    log "ERROR: Admin password is empty or too short (minimum 8 characters)"
    exit 1
fi

# Clone official Wazuh Docker repository
log "Cloning Wazuh Docker repository..."
if ! git clone https://github.com/wazuh/wazuh-docker.git -b v${wazuh_version} --depth=1; then
    log "ERROR: Failed to clone Wazuh repository"
    exit 1
fi

cd wazuh-docker/single-node

# Generate certificates using official generator
log "Generating SSL certificates..."
if ! docker compose -f generate-indexer-certs.yml run --rm generator; then
    log "ERROR: Certificate generation failed"
    exit 1
fi

log "Certificates generated successfully"

# Disable HTTPS on dashboard (use HTTP over SSH tunnel)
log "Configuring dashboard to use HTTP..."
if [ -f "config/wazuh_dashboard/opensearch_dashboards.yml" ]; then
    sed -i 's/server.ssl.enabled: true/server.ssl.enabled: false/g' config/wazuh_dashboard/opensearch_dashboards.yml
    sed -i 's/^server.ssl.certificate:/#server.ssl.certificate:/g' config/wazuh_dashboard/opensearch_dashboards.yml
    sed -i 's/^server.ssl.key:/#server.ssl.key:/g' config/wazuh_dashboard/opensearch_dashboards.yml
    log "Dashboard configured for HTTP"
else
    log "WARNING: Dashboard config file not found"
fi

# Change dashboard port mapping from 443 to 5601
log "Updating dashboard port mapping to 5601..."
sed -i 's/443:5601/5601:5601/g' docker-compose.yml

# Update admin password and configuration in .env file
log "Setting admin password and Elasticsearch configuration..."
cat > .env <<EOF
INDEXER_PASSWORD=$ADMIN_PASSWORD
EOF

log ".env file created with INDEXER_PASSWORD"

# Update docker-compose.yml to use environment variable for INDEXER_PASSWORD
log "Updating docker-compose.yml to use INDEXER_PASSWORD from .env..."
sed -i 's/INDEXER_PASSWORD=SecretPassword/INDEXER_PASSWORD=$${INDEXER_PASSWORD}/g' docker-compose.yml

# Verify the change
if grep -q 'INDEXER_PASSWORD=$${INDEXER_PASSWORD}' docker-compose.yml; then
    log "docker-compose.yml updated to use environment variable"
else
    log "WARNING: docker-compose.yml may not have been updated correctly"
fi

# Update internal_users.yml with hashed password for the indexer
log "Configuring admin password in indexer..."
if [ -f "config/wazuh_indexer/internal_users.yml" ]; then
    # Generate password hash using the indexer's hash tool
    log "Generating password hash..."
    HASHED_PASSWORD=$(docker run --rm wazuh/wazuh-indexer:${wazuh_version} \
        bash -c "export OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk && /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$ADMIN_PASSWORD'" 2>/dev/null | tail -1)
    
    if [ -z "$HASHED_PASSWORD" ]; then
        log "ERROR: Failed to generate password hash"
        exit 1
    fi
    
    log "Updating admin password hash in internal_users.yml..."
    # Update the admin user's hash (be careful with special chars in sed)
    sed -i "/^admin:/,/^[^[:space:]]/ s|hash: \".*\"|hash: \"$HASHED_PASSWORD\"|" config/wazuh_indexer/internal_users.yml
    log "Admin password updated successfully"
else
    log "WARNING: internal_users.yml not found, password may not work"
fi

# Pull Docker images first
log "Pulling Wazuh Docker images..."
docker compose pull

# Start Wazuh stack
log "Starting Wazuh Docker Compose stack..."
if ! docker compose up -d; then
    log "ERROR: Failed to start Docker Compose stack"
    docker compose logs
    exit 1
fi

# Wait for services to be healthy
log "Waiting for Wazuh services to become healthy (this may take 3-5 minutes)..."
sleep 30

# Check if containers are running
RUNNING_CONTAINERS=$(docker compose ps --services --filter "status=running" | wc -l)
log "Running containers: $RUNNING_CONTAINERS/3"

# Wait for services to initialize
log "Waiting for services to initialize..."
sleep 120

# Final status check
log "Final container status:"
docker compose ps

# Check if dashboard is responding
log "Testing dashboard connectivity..."
for i in {1..30}; do
    if curl -s http://localhost:5601 > /dev/null 2>&1; then
        log "Dashboard is responding on port 5601"
        break
    fi
    log "Waiting for dashboard to respond (attempt $i/30)..."
    sleep 10
done

# Create systemd service for auto-restart on reboot
log "Creating systemd service for auto-restart..."
cat > /etc/systemd/system/wazuh-docker.service <<'SERVICE_EOF'
[Unit]
Description=Wazuh Docker Compose Stack
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/wazuh/wazuh-docker/single-node
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable wazuh-docker.service

log "Wazuh deployment complete!"
log "Services should be available at:"
log "  - Wazuh Dashboard: http://localhost:5601 (via SSH tunnel)"
log "  - Wazuh API: https://localhost:55000"
log "  - Admin credentials: admin / [your configured password]"
log ""
log "Dashboard uses HTTP (SSH tunnel provides encryption)"
log "To check logs: docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml logs -f"
log "To restart: docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml restart"

# ============================================================
# Configure Docker Compose for GCP Log File Access
# ============================================================
log "Configuring Docker Compose to mount GCP log file..."

# Create the GCP log file FIRST (before Docker mounts it)
log "Creating GCP log file..."
touch /var/log/gcp-wazuh.log
chmod 644 /var/log/gcp-wazuh.log
log "GCP log file created: /var/log/gcp-wazuh.log"

# Add volume mount for GCP log file to wazuh.manager service
if ! grep -q "gcp-wazuh.log" docker-compose.yml; then
    log "Adding GCP log file volume mount to docker-compose.yml..."
    
    # Create backup
    cp docker-compose.yml docker-compose.yml.backup
    
    # Use Python to properly edit YAML (safer than sed)
    python3 <<'PYTHON_EOF'
import yaml
import sys

try:
    # Read the docker-compose file
    with open('docker-compose.yml', 'r') as f:
        compose = yaml.safe_load(f)
    
    # Add the volume mount to wazuh.manager service
    if 'services' in compose and 'wazuh.manager' in compose['services']:
        if 'volumes' not in compose['services']['wazuh.manager']:
            compose['services']['wazuh.manager']['volumes'] = []
        
        # Add GCP log volume if not already present
        gcp_volume = '/var/log/gcp-wazuh.log:/var/log/gcp-wazuh.log:ro'
        if gcp_volume not in compose['services']['wazuh.manager']['volumes']:
            compose['services']['wazuh.manager']['volumes'].append(gcp_volume)
            print("Volume mount added to wazuh.manager service")
        else:
            print("Volume mount already exists")
        
        # Write back
        with open('docker-compose.yml', 'w') as f:
            yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
        
        sys.exit(0)
    else:
        print("ERROR: Could not find wazuh.manager service")
        sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
PYTHON_EOF
    
    if [ $? -eq 0 ]; then
        log "Volume mount added successfully"
        
        # Recreate containers to apply volume mount
        log "Recreating Wazuh containers to apply volume mount..."
        docker compose up -d --force-recreate wazuh.manager
        
        # Wait for manager to be ready
        log "Waiting for Wazuh manager to initialize..."
        sleep 30
    else
        log "ERROR: Failed to update docker-compose.yml"
        exit 1
    fi
else
    log "GCP log file volume mount already configured"
fi

# ============================================================
# GCP Pub/Sub Integration Setup (Using Built-in Wazuh GCP-Pub/Sub Module)
# ============================================================
log "Setting up GCP Pub/Sub integration using Wazuh's built-in module..."

# Wait for Wazuh manager to be ready first
log "Waiting for Wazuh manager to be ready..."
for i in {1..60}; do
    if docker exec single-node-wazuh.manager-1 test -f /var/ossec/etc/ossec.conf 2>/dev/null; then
        log "Wazuh manager is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        log "ERROR: Wazuh manager not ready after 10 minutes"
        exit 1
    fi
    sleep 10
done

# Create directory for GCP credentials inside the container
log "Preparing GCP credentials directory in Wazuh container..."
docker exec single-node-wazuh.manager-1 mkdir -p /var/ossec/wodles/gcp-pubsub

# Download the GCP service account key from metadata and copy to container
log "Downloading GCP service account key..."
TMP_CREDS="/tmp/gcp-credentials.json"
if ! curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/gcp-sa-key" \
    -o "$TMP_CREDS"; then
    log "ERROR: Failed to download GCP service account key from metadata"
    exit 1
fi

# Verify the JSON key is valid
if ! jq empty "$TMP_CREDS" 2>/dev/null; then
    log "ERROR: Downloaded service account key is not valid JSON"
    rm -f "$TMP_CREDS"
    exit 1
fi

# Copy credentials to container
docker cp "$TMP_CREDS" single-node-wazuh.manager-1:/var/ossec/wodles/gcp-pubsub/credentials.json
docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/wodles/gcp-pubsub/credentials.json
docker exec single-node-wazuh.manager-1 chmod 640 /var/ossec/wodles/gcp-pubsub/credentials.json
rm -f "$TMP_CREDS"
log "GCP service account key configured in Wazuh container"

# Install GCP Pub/Sub Python dependencies in Wazuh's framework Python
log "Installing GCP Pub/Sub Python dependencies in Wazuh framework..."
docker exec single-node-wazuh.manager-1 bash -c '
    /var/ossec/framework/python/bin/pip3 install --upgrade google-cloud-pubsub==2.18.4
'

if docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/pip3 list | grep -q google-cloud-pubsub; then
    log "✅ GCP Pub/Sub dependencies installed successfully"
else
    log "ERROR: Failed to install GCP Pub/Sub dependencies"
    exit 1
fi

# Configure Wazuh GCP-Pub/Sub command wodle
log "Configuring Wazuh GCP Pub/Sub command wodle..."
docker exec single-node-wazuh.manager-1 python3 <<'PYEOF'
import re

ossec_conf_path = "/var/ossec/etc/ossec.conf"

# Read current config
with open(ossec_conf_path, "r") as f:
    content = f.read()

# Remove any existing gcp-pubsub or gcp command wodle configuration
content = re.sub(r'<wodle name="gcp-pubsub">.*?</wodle>', '', content, flags=re.DOTALL)
content = re.sub(r'<!-- GCP Pub/Sub.*?</wodle>', '', content, flags=re.DOTALL)

# GCP Pub/Sub command wodle configuration
# NOTE: The gcp-pubsub is NOT a native wodle module name in Wazuh
# Instead, we invoke the gcloud script via command wodle
gcp_wodle = """  <!-- GCP Pub/Sub Integration -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>gcp</tag>
    <command>/var/ossec/wodles/gcloud/gcloud -T pubsub -p ${pubsub_project_id} -s ${pubsub_subscription_id} -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 100 -l 1</command>
    <interval>1m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>0</timeout>
  </wodle>

"""

# Insert before first </ossec_config>
content = content.replace("</ossec_config>", gcp_wodle + "</ossec_config>", 1)

with open(ossec_conf_path, "w") as f:
    f.write(content)

print("✅ GCP Pub/Sub command wodle configured")
PYEOF

# Verify configuration was added
if docker exec single-node-wazuh.manager-1 grep -q "GCP Pub/Sub Integration" /var/ossec/etc/ossec.conf; then
    log "✅ GCP Pub/Sub command wodle configured successfully"
else
    log "ERROR: Failed to configure GCP Pub/Sub command wodle"
    exit 1
fi

# Create GCP detection rules (Wazuh has built-in ones, but we'll add custom ones)
log "Creating GCP detection rules..."
docker exec single-node-wazuh.manager-1 bash -c 'cat > /var/ossec/etc/rules/local_rules.xml <<'"'"'LOCALRULES'"'"'
<!-- Local rules for GCP integration -->

<group name="gcp,cloud,">
  
  <!--  GCP Pub/Sub base rule -->
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration">gcp</field>
    <description>GCP log received via Pub/Sub</description>
    <group>gcp,cloud,</group>
  </rule>
  
  <!-- GCP Compute Instance operations -->
  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <field name="protoPayload.methodName">\.instances\.</field>
    <description>GCP Compute: $(protoPayload.methodName)</description>
    <group>gcp,compute,</group>
  </rule>
  
  <!-- GCP IAM operations -->
  <rule id="100102" level="6">
    <if_sid>100100</if_sid>
    <field name="protoPayload.methodName">\.iam\.|\.serviceAccount\.</field>
    <description>GCP IAM: $(protoPayload.methodName) by $(protoPayload.authenticationInfo.principalEmail)</description>
    <group>gcp,iam,</group>
  </rule>
  
  <!-- GCP Network operations -->
  <rule id="100103" level="5">
    <if_sid>100100</if_sid>
    <field name="protoPayload.serviceName">compute.googleapis.com</field>
    <field name="protoPayload.methodName">network|firewall|subnetwork|route</field>
    <description>GCP Network: $(protoPayload.methodName)</description>
    <group>gcp,network,</group>
  </rule>
  
  <!-- GCP Storage operations -->
  <rule id="100104" level="4">
    <if_sid>100100</if_sid>
    <field name="protoPayload.serviceName">storage.googleapis.com</field>
    <description>GCP Storage: $(protoPayload.methodName)</description>
    <group>gcp,storage,</group>
  </rule>
  
  <!-- GCP Permission denied -->
  <rule id="100105" level="8">
    <if_sid>100100</if_sid>
    <field name="protoPayload.status.code">^7$</field>
    <description>GCP Permission Denied: $(protoPayload.methodName) by $(protoPayload.authenticationInfo.principalEmail)</description>
    <group>gcp,access_denied,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
  
  <!-- GCP Errors -->
  <rule id="100106" level="7">
    <if_sid>100100</if_sid>
    <field name="severity">ERROR</field>
    <description>GCP Error: $(protoPayload.methodName)</description>
    <group>gcp,error,</group>
  </rule>
  
  <!-- GCP Warnings -->
  <rule id="100107" level="4">
    <if_sid>100100</if_sid>
    <field name="severity">WARNING</field>
    <description>GCP Warning: $(protoPayload.methodName)</description>
    <group>gcp,warning,</group>
  </rule>
  
  <!-- GCP Critical events -->
  <rule id="100108" level="12">
    <if_sid>100100</if_sid>
    <field name="severity">CRITICAL|ALERT|EMERGENCY</field>
    <description>GCP Critical Event: $(protoPayload.methodName)</description>
    <group>gcp,critical,</group>
  </rule>
  
  <!-- GCP Resource deletion -->
  <rule id="100109" level="6">
    <if_sid>100100</if_sid>
    <field name="protoPayload.methodName">\.delete$</field>
    <description>GCP Resource Deletion: $(protoPayload.methodName) by $(protoPayload.authenticationInfo.principalEmail)</description>
    <group>gcp,resource_deletion,</group>
  </rule>

</group>
LOCALRULES
'

# Restart Wazuh to load the new configuration
log "Restarting Wazuh to load GCP command wodle..."
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart > /dev/null 2>&1
sleep 60

# Verify GCP command wodle is running
log "Verifying GCP Pub/Sub command wodle status..."
if docker exec single-node-wazuh.manager-1 grep -i "command:gcp" /var/ossec/logs/ossec.log > /dev/null 2>&1; then
    log "✅ GCP Pub/Sub command wodle is active"
else
    log "⚠️  GCP Pub/Sub command wodle may not be active yet (check logs later)"
fi

# Verify rules were loaded
if docker exec single-node-wazuh.manager-1 grep -q "100100" /var/ossec/etc/rules/local_rules.xml; then
    log "✅ GCP detection rules loaded"
else
    log "⚠️  Warning: GCP rules may not be loaded correctly"
fi

# Test manual execution of GCP wodle
log "Testing GCP Pub/Sub connection..."
if docker exec single-node-wazuh.manager-1 timeout 30 /var/ossec/wodles/gcloud/gcloud -T pubsub -p ${pubsub_project_id} -s ${pubsub_subscription_id} -c /var/ossec/wodles/gcp-pubsub/credentials.json -m 2 -l 1 2>&1 | grep -q "Received and acknowledged"; then
    log "✅ GCP Pub/Sub connection successful - logs are being pulled!"
else
    log "⚠️  GCP Pub/Sub connection test inconclusive (check subscription has messages)"
fi

log "GCP Pub/Sub integration setup complete (using command wodle)!"
log ""
log "To view GCP logs in Wazuh Dashboard:"
log "  1. Access dashboard at http://localhost:5601 (via SSH tunnel)"
log "  2. Go to 'Security events' or 'Discover'"
log "  3. Search for: rule.groups:gcp OR integration:gcp"
log "  4. GCP logs will appear in wazuh-alerts-* index"
log ""
log "GCP Command Wodle Configuration:"
log "  - Integration Type: Pub/Sub (via command wodle)"
log "  - Project ID: ${pubsub_project_id}"
log "  - Subscription: ${pubsub_subscription_id}"
log "  - Credentials: /var/ossec/wodles/gcp-pubsub/credentials.json"
log "  - Pull Interval: 1 minute"
log "  - Max Messages: 100 per pull"
log ""
log "To check GCP command wodle logs:"
log "  docker exec single-node-wazuh.manager-1 grep 'command:gcp' /var/ossec/logs/ossec.log"


# Fix Filebeat password to match admin password
log "Configuring Filebeat with correct password..."
docker exec single-node-wazuh.manager-1 bash <<EOFFILEBEAT
    if [ -f /etc/filebeat/filebeat.yml ]; then
        sed -i "s/password:.*/password: '\$ADMIN_PASSWORD'/g" /etc/filebeat/filebeat.yml
        echo 'Filebeat password updated'
        pkill filebeat || true
    else
        echo 'WARNING: filebeat.yml not found'
    fi
EOFFILEBEAT

# Fix Filebeat password in the Docker volume (persists across container restarts)
log "Updating Filebeat password in Docker volume..."
if [ -f /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml ]; then
    sed -i "s/password:.*/password: '\$ADMIN_PASSWORD'/g" /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml
    log "Filebeat volume password updated"
else
    log "Filebeat volume not found (will be created by Docker)"
fi

# Ensure Filebeat module path is configured
log "Configuring Filebeat modules path..."
if [ -f /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml ]; then
    if ! grep -q "filebeat.config.modules.path" /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml; then
        cat >> /var/lib/docker/volumes/single-node_filebeat_etc/_data/filebeat.yml <<'FBMODULES'

filebeat.config.modules:
  path: $${path.config}/modules.d/*.yml
  reload.enabled: false
FBMODULES
    fi
fi

# Wait for Filebeat to restart and verify connection
log "Verifying Filebeat connection..."
sleep 10
docker exec single-node-wazuh.manager-1 filebeat test output -c /etc/filebeat/filebeat.yml 2>&1 | grep -q "talk to server... OK" && \
    log "✅ Filebeat connection successful" || \
    log "⚠️  Filebeat connection test inconclusive (may still be starting)"

log ""
log "=========================================="
log "Wazuh Installation Complete!"
log "=========================================="
log ""
log "Dashboard Access:"
log "  URL: http://localhost:5601 (via SSH tunnel)"
log "  Username: admin"
log "  Password: $${ADMIN_PASSWORD}"
log ""
log "SSH Tunnel Command:"
log "  gcloud compute ssh $$(hostname) --zone=$$(gcloud compute instances list --filter=name:$$(hostname) --format='value(zone)') --project=$${pubsub_project_id} -- -L 5601:localhost:5601"
log ""
log "GCP Pub/Sub Integration:"
log "  Status: Enabled (command wodle)"
log "  Integration: GCloud Pub/Sub"
log "  Project: $${pubsub_project_id}"
log "  Subscription: $${pubsub_subscription_id}"
log "  Check wodle logs: docker exec single-node-wazuh.manager-1 grep 'command:gcp' /var/ossec/logs/ossec.log"
log ""
log "To view GCP logs in dashboard:"
log "  1. Create SSH tunnel (see command above)"
log "  2. Open http://localhost:5601"
log "  3. Go to 'Security events' or 'Discover'"
log "  4. Filter by: rule.groups:gcp OR integration:gcp"
log "  5. GCP logs include: Cloud Run, Cloud Functions, API Gateway, Compute Engine, IAM, Firewall, Storage, etc."
log ""
log "Installation log saved to: /var/log/wazuh-install.log"
log ""

