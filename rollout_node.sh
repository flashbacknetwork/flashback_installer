#!/usr/bin/env bash

set -euo pipefail

# Rollout script for a Flashback node on Ubuntu 22.04/24.04
# - Installs Docker and Compose
# - Prepares /opt/flashback directory
# - Normalizes SSL cert filenames for S3/GCS/BLOB endpoints
# - Generates .env files for S3/GCS/BLOB with SELF_URL/SELF_REGION/ORG_ID
# - Generates nginx prod config from inputs
# - Writes docker-compose.yml and starts services

########################################
# Defaults and CLI parsing
########################################

REGION=""
PROVIDER=""  # Optional, when provided it is included in domains
ROOT_DOMAIN=""  # e.g., mycompany.com
BACKEND_URL="https://backend.flashback.tech"
ORG_ID=""
KEY_PRIVATE_LOCAL_PATH=""  # Path on this machine to RSA private key to copy
NETWORK_JSON_LOCAL_PATH=""  # Optional: flashback-network-delegated.json local path to copy

usage() {
  echo "Usage: $0 -r <region> -d <root-domain> [-p <provider>] [-b <backend-url>] -o <org-id> -k <path-to-private-key> [-n <path-to-network-json>]" >&2
  echo "Examples:" >&2
  echo "  $0 -r eu-central-1 -d mycompany.com -p aws -o <ORG_ID> -k ~/keyR_private.pem" >&2
  echo "  $0 -r us-east-1 -d mycompany.com -o <ORG_ID> -k ./keyR_private.pem -b https://backend.flashback.tech" >&2
}

while getopts ":r:p:d:b:o:k:n:h" opt; do
  case "$opt" in
    r) REGION="$OPTARG" ;;
    p) PROVIDER="$OPTARG" ;;
    d) ROOT_DOMAIN="$OPTARG" ;;
    b) BACKEND_URL="$OPTARG" ;;
    o) ORG_ID="$OPTARG" ;;
    k) KEY_PRIVATE_LOCAL_PATH="$OPTARG" ;;
    n) NETWORK_JSON_LOCAL_PATH="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Option -$OPTARG requires an argument" >&2; usage; exit 1 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$REGION" || -z "$ROOT_DOMAIN" || -z "$ORG_ID" || -z "$KEY_PRIVATE_LOCAL_PATH" ]]; then
  echo "Missing required arguments." >&2
  usage
  exit 1
fi

if [[ ! -f "$KEY_PRIVATE_LOCAL_PATH" ]]; then
  echo "Private key file not found: $KEY_PRIVATE_LOCAL_PATH" >&2
  exit 1
fi

########################################
# Derived names
########################################

suffix="-$REGION"
if [[ -n "$PROVIDER" ]]; then
  suffix="-$REGION-$PROVIDER"
fi

S3_DOMAIN="s3$suffix.$ROOT_DOMAIN"
GCS_DOMAIN="gcs$suffix.$ROOT_DOMAIN"
BLOB_DOMAIN="blob$suffix.$ROOT_DOMAIN"

S3_CERT_NAME="s3$suffix.crt"
S3_KEY_NAME="s3$suffix.key"
GCS_CERT_NAME="gcs$suffix.crt"
GCS_KEY_NAME="gcs$suffix.key"
BLOB_CERT_NAME="blob$suffix.crt"
BLOB_KEY_NAME="blob$suffix.key"

FLASHBACK_DIR="/opt/flashback"
NGINX_CONF_DIR="$FLASHBACK_DIR/nginx/conf.d/prod"
NGINX_SSL_DIR="$FLASHBACK_DIR/nginx/ssl"
NGINX_LOG_DIR="$FLASHBACK_DIR/nginx/logs"

########################################
# System preparation (Ubuntu 22/24)
########################################

echo "[1/7] Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y || true
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release software-properties-common jq

echo "[2/7] Installing Docker and Compose..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo systemctl enable docker
  sudo systemctl start docker
  if id -nG "$USER" | grep -qw docker; then
    :
  else
    sudo usermod -aG docker "$USER" || true
  fi
else
  echo "Docker already installed."
fi

echo "[3/7] Preparing directories under $FLASHBACK_DIR ..."
sudo mkdir -p "$NGINX_CONF_DIR"
sudo mkdir -p "$NGINX_SSL_DIR"
sudo mkdir -p "$NGINX_LOG_DIR"
sudo chown -R "$USER":"$USER" "$FLASHBACK_DIR"

########################################
# Copy assets and normalize filenames
########################################

echo "[4/7] Copying key and optional network JSON..."
cp "$KEY_PRIVATE_LOCAL_PATH" "$FLASHBACK_DIR/keyR_private.pem"
chmod 600 "$FLASHBACK_DIR/keyR_private.pem"

if [[ -n "${NETWORK_JSON_LOCAL_PATH}" ]]; then
  if [[ -f "$NETWORK_JSON_LOCAL_PATH" ]]; then
    cp "$NETWORK_JSON_LOCAL_PATH" "$FLASHBACK_DIR/flashback-network-delegated.json"
  else
    echo "Warning: NETWORK_JSON_LOCAL_PATH provided but not found: $NETWORK_JSON_LOCAL_PATH" >&2
  fi
fi

echo "You now need to ensure the three certificate pairs exist on this machine."
echo "You can scp them with any filenames, then provide the paths here for normalization."

read -r -p "Path to S3 cert (.crt): " S3_CERT_SRC
read -r -p "Path to S3 key  (.key): " S3_KEY_SRC
read -r -p "Path to GCS cert (.crt): " GCS_CERT_SRC
read -r -p "Path to GCS key  (.key): " GCS_KEY_SRC
read -r -p "Path to BLOB cert (.crt): " BLOB_CERT_SRC
read -r -p "Path to BLOB key  (.key): " BLOB_KEY_SRC

for f in "$S3_CERT_SRC" "$S3_KEY_SRC" "$GCS_CERT_SRC" "$GCS_KEY_SRC" "$BLOB_CERT_SRC" "$BLOB_KEY_SRC"; do
  if [[ ! -f "$f" ]]; then
    echo "File not found: $f" >&2
    exit 1
  fi
done

cp "$S3_CERT_SRC" "$NGINX_SSL_DIR/$S3_CERT_NAME"
cp "$S3_KEY_SRC"  "$NGINX_SSL_DIR/$S3_KEY_NAME"
cp "$GCS_CERT_SRC" "$NGINX_SSL_DIR/$GCS_CERT_NAME"
cp "$GCS_KEY_SRC"  "$NGINX_SSL_DIR/$GCS_KEY_NAME"
cp "$BLOB_CERT_SRC" "$NGINX_SSL_DIR/$BLOB_CERT_NAME"
cp "$BLOB_KEY_SRC"  "$NGINX_SSL_DIR/$BLOB_KEY_NAME"

chmod 600 "$NGINX_SSL_DIR/$S3_KEY_NAME" "$NGINX_SSL_DIR/$GCS_KEY_NAME" "$NGINX_SSL_DIR/$BLOB_KEY_NAME"
chmod 644 "$NGINX_SSL_DIR/$S3_CERT_NAME" "$NGINX_SSL_DIR/$GCS_CERT_NAME" "$NGINX_SSL_DIR/$BLOB_CERT_NAME"

########################################
# Fetch .env files for services from backend
########################################

echo "[5/7] Fetching env files from backend /secrets..."

# Determine public IP for signing per backend contract
IP=$(curl -s https://ifconfig.me || curl -s https://api.ipify.org || true)
if [[ -z "$IP" ]]; then
  echo "Error: could not determine public IP for secrets request" >&2; exit 1;
fi

TIMESTAMP=$(date +%s)
# Signature message: ip|region|timestamp or ip|region|timestamp|id_org if provided
if [[ -n "$ORG_ID" ]]; then
  SIGN_MSG="${IP}|${REGION}|${TIMESTAMP}|${ORG_ID}"
else
  SIGN_MSG="${IP}|${REGION}|${TIMESTAMP}"
fi
REQ_SIGNATURE=$(echo -n "$SIGN_MSG" | openssl dgst -sha256 -sign "$FLASHBACK_DIR/keyR_private.pem" | base64 -w 0)

SECRETS_PAYLOAD=$(jq -nc \
  --arg ip "$IP" \
  --arg region "$REGION" \
  --argjson timestamp "$TIMESTAMP" \
  --arg signature "$REQ_SIGNATURE" \
  --arg id_org "$ORG_ID" \
  '{ip:$ip,region:$region,timestamp:$timestamp,signature:$signature} + ( $id_org | length > 0 ? {id_org:$id_org} : {} )')

SECRETS_RESP=$(curl -sS -X POST "${BACKEND_URL%/}/secrets" -H "Content-Type: application/json" -d "$SECRETS_PAYLOAD") || {
  echo "Error: failed to fetch secrets from backend" >&2; exit 1; }

write_env_or_decrypt() {
  local json="$1" key_plain="$2" key_enc="$3" out_path="$4"
  local has_plain has_enc
  has_plain=$(echo "$json" | jq -r "has(\"$key_plain\")")
  has_enc=$(echo "$json" | jq -r "has(\"$key_enc\")")
  if [[ "$has_plain" == "true" ]]; then
    echo "$json" | jq -r ".${key_plain}" | base64 -d > "$out_path"
    return 0
  fi
  if [[ "$has_enc" == "true" ]]; then
    # key_enc is a JSON string with fields: key, iv, ct, mac (all base64)
    local enc_json
    enc_json=$(echo "$json" | jq -r ".${key_enc} | fromjson")
    local key_b64 iv_b64 ct_b64 mac_b64
    key_b64=$(echo "$enc_json" | jq -r '.key')
    iv_b64=$(echo  "$enc_json" | jq -r '.iv')
    ct_b64=$(echo  "$enc_json" | jq -r '.ct')
    mac_b64=$(echo "$enc_json" | jq -r '.mac')

    # Temp files
    local tmp_key tmp_iv tmp_ct tmp_mac_calc tmp_out
    tmp_key=$(mktemp)
    tmp_iv=$(mktemp)
    tmp_ct=$(mktemp)
    tmp_mac_calc=$(mktemp)
    tmp_out=$(mktemp)

    # Decode inputs
    echo "$iv_b64" | base64 -d > "$tmp_iv"
    echo "$ct_b64" | base64 -d > "$tmp_ct"

    # Decrypt AES key with RSA-OAEP(SHA-256)
    echo "$key_b64" | base64 -d \
      | openssl pkeyutl -decrypt -inkey "$FLASHBACK_DIR/keyR_private.pem" \
          -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 > "$tmp_key"

    # Verify HMAC-SHA256 over (iv || ct)
    local key_hex iv_hex mac_calc
    key_hex=$(xxd -p -c256 "$tmp_key")
    iv_hex=$(xxd -p -c256 "$tmp_iv")
    cat "$tmp_iv" "$tmp_ct" \
      | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$key_hex" -binary \
      | base64 > "$tmp_mac_calc"
    mac_calc=$(cat "$tmp_mac_calc")
    if [[ "$mac_calc" != "$mac_b64" ]]; then
      rm -f "$tmp_key" "$tmp_iv" "$tmp_ct" "$tmp_mac_calc" "$tmp_out"
      echo "Error: HMAC verification failed for $key_enc" >&2
      return 1
    fi

    # Decrypt AES-256-CTR
    openssl enc -d -aes-256-ctr -K "$key_hex" -iv "$iv_hex" -in "$tmp_ct" -out "$tmp_out" -nosalt
    mv "$tmp_out" "$out_path"
    rm -f "$tmp_key" "$tmp_iv" "$tmp_ct" "$tmp_mac_calc"
    return 0
  fi
  echo "Error: neither $key_plain nor $key_enc present in secrets response" >&2
  return 1
}

write_env_or_decrypt "$SECRETS_RESP" env_s3 env_s3_enc "$FLASHBACK_DIR/.env.s3"
write_env_or_decrypt "$SECRETS_RESP" env_gcs env_gcs_enc "$FLASHBACK_DIR/.env.gcs"
write_env_or_decrypt "$SECRETS_RESP" env_blob env_blob_enc "$FLASHBACK_DIR/.env.blob"

# Append dynamic variables
{
  echo ""
  echo "ORG_ID=$ORG_ID"
  echo "SELF_URL=https://$S3_DOMAIN"
  echo "SELF_REGION=$REGION"
} >> "$FLASHBACK_DIR/.env.s3"

{
  echo ""
  echo "ORG_ID=$ORG_ID"
  echo "SELF_URL=https://$GCS_DOMAIN"
  echo "SELF_REGION=$REGION"
} >> "$FLASHBACK_DIR/.env.gcs"

{
  echo ""
  echo "ORG_ID=$ORG_ID"
  echo "SELF_URL=https://$BLOB_DOMAIN"
  echo "SELF_REGION=$REGION"
} >> "$FLASHBACK_DIR/.env.blob"

########################################
# Generate nginx config
########################################

echo "[6/7] Generating nginx config..."
cat > "$NGINX_CONF_DIR/default.prod.conf" <<EOF
# Rate limiting configuration
limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_status 429;

# Request size limits
client_max_body_size 100M;
client_body_buffer_size 2M;

# Timeouts
client_header_timeout 60;
client_body_timeout 60;

# Buffer settings for large file uploads
proxy_request_buffering off;
proxy_buffering off;
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;

# HTTP server blocks for API endpoints
server {
    listen 80;
    listen [::]:80;
    server_name "~^(?:(?<bucket>[^.]+)\.)?${S3_DOMAIN//./\\.}$";
    return 301 https://\$host\$request_uri;
}

server {
    listen 80;
    listen [::]:80;
    server_name "~^${GCS_DOMAIN//./\\.}$";
    return 301 https://\$host\$request_uri;
}

server {
    listen 80;
    listen [::]:80;
    server_name "~^(?:(?<storageaccount>[^.]+)\.)?${BLOB_DOMAIN//./\\.}$";
    return 301 https://\$host\$request_uri;
}

# HTTPS server blocks for API endpoints
# S3
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name "~^(?:(?<bucket>[^.]+)\.)?${S3_DOMAIN//./\\.}$";

    # Add resolver for Docker DNS
    resolver 127.0.0.1 ipv6=off valid=30s;

    ssl_certificate /etc/nginx/ssl/$S3_CERT_NAME;
    ssl_certificate_key /etc/nginx/ssl/$S3_KEY_NAME;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # SSL session settings
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    set \$api "s3";
    set \$provider "${PROVIDER}";

    location / {
        # Apply rate limiting
        limit_req zone=api_limit burst=20 nodelay;

        # Set dynamic upstream
        set \$upstream "http://s3-api:3000";

        # Pass the subdomain information as headers
        proxy_set_header X-Bucket-Name \$bucket;
        proxy_set_header X-API-Format \$api;
        proxy_set_header X-Region "$REGION";
        proxy_set_header X-Provider \$provider;

        # Standard proxy headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Streaming settings
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;

        # Route to appropriate service
        proxy_pass \$upstream;

        # Logging
        access_log /var/log/nginx/api_access.log combined buffer=512k flush=1m;
        error_log /var/log/nginx/api_error.log warn;
    }
}

# GCS
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name "~^${GCS_DOMAIN//./\\.}$";

    # Add resolver for Docker DNS
    resolver 127.0.0.1 ipv6=off valid=30s;

    ssl_certificate /etc/nginx/ssl/$GCS_CERT_NAME;
    ssl_certificate_key /etc/nginx/ssl/$GCS_KEY_NAME;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    set \$api "gcs";
    set \$provider "${PROVIDER}";

    location / {
        # Set dynamic upstream
        set \$upstream "http://gcs-api:3001";

        # Pass the subdomain information as headers
        proxy_set_header X-API-Format \$api;
        proxy_set_header X-Region "$REGION";
        proxy_set_header X-Provider \$provider;

        # Standard proxy headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Route to appropriate service
        proxy_pass \$upstream;
    }
}

# Azure Blob Storage
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name "~^(?:(?<storageaccount>[^.]+)\.)?${BLOB_DOMAIN//./\\.}$";

    # Add resolver for Docker DNS
    resolver 127.0.0.1 ipv6=off valid=30s;

    ssl_certificate /etc/nginx/ssl/$BLOB_CERT_NAME;
    ssl_certificate_key /etc/nginx/ssl/$BLOB_KEY_NAME;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    set \$api "blob";
    set \$provider "${PROVIDER}";

    location / {
        # Set dynamic upstream
        set \$upstream "http://blob-api:3002";

        # Pass the storage account information as header
        proxy_set_header X-Storage-Account \$storageaccount;
        proxy_set_header X-API-Format \$api;
        proxy_set_header X-Region "$REGION";
        proxy_set_header X-Provider \$provider;

        # Standard proxy headers
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Route to appropriate service
        proxy_pass \$upstream;
    }
}
EOF

########################################
# Docker Compose and startup
########################################

echo "[7/7] Writing docker-compose.yml and starting services..."
cat > "$FLASHBACK_DIR/docker-compose.yml" <<EOF
version: '3.3'
services:
  nginx:
    image: nginx:1.25-alpine
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - $NGINX_CONF_DIR/default.prod.conf:/etc/nginx/conf.d/default.conf
      - $NGINX_SSL_DIR/$S3_CERT_NAME:/etc/nginx/ssl/$S3_CERT_NAME
      - $NGINX_SSL_DIR/$S3_KEY_NAME:/etc/nginx/ssl/$S3_KEY_NAME
      - $NGINX_SSL_DIR/$GCS_CERT_NAME:/etc/nginx/ssl/$GCS_CERT_NAME
      - $NGINX_SSL_DIR/$GCS_KEY_NAME:/etc/nginx/ssl/$GCS_KEY_NAME
      - $NGINX_SSL_DIR/$BLOB_CERT_NAME:/etc/nginx/ssl/$BLOB_CERT_NAME
      - $NGINX_SSL_DIR/$BLOB_KEY_NAME:/etc/nginx/ssl/$BLOB_KEY_NAME
      - $NGINX_LOG_DIR:/var/log/nginx
    networks:
      - api-net

  s3-api:
    image: docker.io/javierortiz4flashback/flashonrust:latest
    container_name: s3-api
    restart: unless-stopped
    env_file:
      - $FLASHBACK_DIR/.env.s3
    environment:
      - REGION=$REGION
    volumes:
      - $FLASHBACK_DIR/flashback-network-delegated.json:/app/flashback-network-delegated.json
      - $FLASHBACK_DIR/keyR_private.pem:/app/keyR_private.pem
    networks:
      - api-net

  gcs-api:
    image: docker.io/javierortiz4flashback/flashonrust:latest
    container_name: gcs-api
    restart: unless-stopped
    env_file:
      - $FLASHBACK_DIR/.env.gcs
    environment:
      - REGION=$REGION
    volumes:
      - $FLASHBACK_DIR/flashback-network-delegated.json:/app/flashback-network-delegated.json
      - $FLASHBACK_DIR/keyR_private.pem:/app/keyR_private.pem
    networks:
      - api-net

  blob-api:
    image: docker.io/javierortiz4flashback/flashonrust:latest
    container_name: blob-api
    restart: unless-stopped
    env_file:
      - $FLASHBACK_DIR/.env.blob
    environment:
      - REGION=$REGION
    volumes:
      - $FLASHBACK_DIR/flashback-network-delegated.json:/app/flashback-network-delegated.json
      - $FLASHBACK_DIR/keyR_private.pem:/app/keyR_private.pem
    networks:
      - api-net

networks:
  api-net:
    driver: bridge
EOF

pushd "$FLASHBACK_DIR" >/dev/null
docker --version
docker compose version || true
sudo docker pull --platform linux/amd64 docker.io/javierortiz4flashback/flashonrust:latest || true
sudo docker compose down || true
sudo docker compose up -d
echo "Containers:"
sudo docker ps
echo "Logs (first lines):"
sudo docker logs --tail 50 s3-api || true
sudo docker logs --tail 50 gcs-api || true
sudo docker logs --tail 50 blob-api || true
sudo docker logs --tail 50 nginx-proxy || true
popd >/dev/null

########################################
# Node registration
########################################

echo "Registering node with backend..."
IP=$(curl -s https://ifconfig.me || curl -s https://api.ipify.org || true)
if [[ -z "$IP" ]]; then
  echo "Warning: could not determine public IP automatically; please ensure connectivity. Skipping registration." >&2
else
  TIMESTAMP=$(date +%s)
  MESSAGE="${IP}|${REGION}|${TIMESTAMP}"
  SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -sign "$FLASHBACK_DIR/keyR_private.pem" | base64 -w 0)
  UPPER_PROVIDER="${PROVIDER^^}"
  NODE_VERSION="0.0.28"
  PAYLOAD=$(jq -nc \
    --arg provider "$UPPER_PROVIDER" \
    --arg region "$REGION" \
    --arg ip "$IP" \
    --arg status "running" \
    --arg version "$NODE_VERSION" \
    --argjson timestamp "$TIMESTAMP" \
    --arg signature "$SIGNATURE" \
    --arg org_id "$ORG_ID" \
    '{provider:$provider,region:$region,ip:$ip,status:$status,version:$version,timestamp:$timestamp,signature:$signature,org_id:$org_id}')
  if [[ -z "$UPPER_PROVIDER" ]]; then
    # Remove provider field if empty
    PAYLOAD=$(echo "$PAYLOAD" | jq 'del(.provider)')
  fi
  curl -sS -X POST "${BACKEND_URL%/}/register" \
       -H "Content-Type: application/json" \
       -d "$PAYLOAD" || echo "Warning: registration request failed"
fi

echo "\nRollout complete."
echo "- S3:  https://$S3_DOMAIN"
echo "- GCS: https://$GCS_DOMAIN"
echo "- BLOB: https://$BLOB_DOMAIN"
echo "Note: If you were newly added to the docker group, you may need to log out/in."


