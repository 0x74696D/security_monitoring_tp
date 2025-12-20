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
    jq

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

# Update admin password in .env file
log "Setting admin password..."
if [ -f ".env" ]; then
    sed -i "s/INDEXER_PASSWORD=.*/INDEXER_PASSWORD=$ADMIN_PASSWORD/g" .env
else
    echo "INDEXER_PASSWORD=$ADMIN_PASSWORD" > .env
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

