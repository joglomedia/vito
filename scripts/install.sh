#!/usr/bin/env bash

{ # This ensures the entire script is downloaded #

# VitoDeploy header banner
function vitodeploy_header() {
  clear

  ASCII_LOGO="
#   __      ___ _        _____             _              
#   \ \    / (_) |      |  __ \           | |             
#    \ \  / / _| |_ ___ | |  | | ___ _ __ | | ___  _   _  
#     \ \/ / | | __/ _ \| |  | |/ _ \ '_ \| |/ _ \| | | | 
#      \  /  | | || (_) | |__| |  __/ |_) | | (_) | |_| | 
#    ___\/   |_|\__\___/|_____/ \___| .__/|_|\___/ \__, | 
#   |_   _|         | |      | | |  | |      |__ \  __/ | 
#     | |  _ __  ___| |_ __ _| | | _|_|_ __     ) ||___/__
#     | | | '_ \/ __| __/ _' | | |/ _ \ '__|   / /  \ \/ /
#    _| |_| | | \__ \ || (_| | | |  __/ |     / /_ _ >  < 
#   |_____|_| |_|___/\__\__,_|_|_|\___|_|    |____(_)_/\_\ 
#                                                         
#############################################################
"                                                        

  # Define the color gradient (shades of blue and cyan)
  COLORS=(
    '\033[38;5;45m' # Royal Blue
    '\033[38;5;51m' # Cornflower Blue
    '\033[38;5;57m' # Deep Sky Blue
    '\033[38;5;63m' # Dodger Blue
    '\033[38;5;69m' # Sky Blue
    '\033[38;5;75m' # Light Blue
    '\033[38;5;81m' # Cyan
  )

  # Split the ASCII art into lines
  _IFS=${IFS}
  IFS=$'\n' read -rd '' -a LINES <<<"${ASCII_LOGO}"

  # Print each line with the corresponding color
  for i in "${!LINES[@]}"; do
    COLOR_INDEX=$((i % ${#COLORS[@]}))
    echo -e "${COLORS[COLOR_INDEX]}${LINES[i]}"
  done

  # End color
  echo -e -n "\e[0m\n"

  # Restore default IFS
  IFS=${_IFS}
}

# Handle user input
function vitodeploy_input() {
  # Detect server IP address
  export V_SERVER_IP_PRIVATE && V_SERVER_IP_PRIVATE=${V_SERVER_IP_PRIVATE:-$(get_ip_private)}
  export V_SERVER_IP_PUBLIC && V_SERVER_IP_PUBLIC=${V_SERVER_IP_PUBLIC:-$(get_ip_public)}
  export V_SERVER_IPV6_PRIVATE && V_SERVER_IPV6_PRIVATE=${V_SERVER_IPV6_PRIVATE:-$(get_ipv6_private)}
  export V_SERVER_IPV6_PUBLIC && V_SERVER_IPV6_PUBLIC=${V_SERVER_IPV6_PUBLIC:-$(get_ipv6_public)}

  export V_USERNAME
  while [[ -z "${V_USERNAME}" ]]; do
    read -rp "System account username [vito]: " -e V_USERNAME
  done

  if [[ -z "${V_PASSWORD}" ]]; then
    export V_PASSWORD && V_PASSWORD=$(openssl rand -base64 12)
  fi

  export V_ADMIN_EMAIL
  while [[ -z "${V_ADMIN_EMAIL}" || $(validate_email_address "${V_ADMIN_EMAIL}") == false ]]; do
    read -rp "Vito dashboard admin email: " -e V_ADMIN_EMAIL
  done

  export V_ADMIN_PASSWORD
  while [[ -z "${V_ADMIN_PASSWORD}" ]]; do
    read -rp "Vito dashboard admin password: " -e V_ADMIN_PASSWORD
  done

  export V_APP_ENV
  while [[ "${V_APP_ENV}" != prod* && "${V_APP_ENV}" != local* ]]; do
    read -rp "Vito environment [production/local]: " -i production -e V_APP_ENV
  done

  export V_USE_CUSTOM_DOMAIN
  export V_CUSTOM_DOMAIN
  export V_APP_URL

  if [[ "${V_APP_ENV}" == prod* ]]; then
    while [[ "${V_USE_CUSTOM_DOMAIN}" != y* && "${V_USE_CUSTOM_DOMAIN}" != Y* && \
      "${V_USE_CUSTOM_DOMAIN}" != n* && "${V_USE_CUSTOM_DOMAIN}" != N* ]];
    do
      read -rp "Do you wish to setup Vito with a custom domain? [y/n]: " -e V_USE_CUSTOM_DOMAIN
    done

    if [[ "${V_USE_CUSTOM_DOMAIN}" == y* || "${V_USE_CUSTOM_DOMAIN}" == Y* ]]; then
      while [[ -z "${V_CUSTOM_DOMAIN}" || $(validate_domain_name "${V_CUSTOM_DOMAIN}") == false ]]; do
        read -rp "Your valid domain name [mydomain.com]: " -e V_CUSTOM_DOMAIN
      done

      while [[ "${V_USE_HTTPS_DOMAIN}" != y* && "${V_USE_HTTPS_DOMAIN}" != Y* && \
        "${V_USE_HTTPS_DOMAIN}" != n* && "${V_USE_HTTPS_DOMAIN}" != N* ]];
      do
        read -rp "Do you wish to enable HTTPS for your domain? [y/n]: " -e V_USE_HTTPS_DOMAIN
      done

      if [[ "${V_USE_HTTPS_DOMAIN}" == y* || "${V_USE_HTTPS_DOMAIN}" == Y* ]]; then
        V_APP_URL="https://${V_CUSTOM_DOMAIN}"
      else
        V_APP_URL="http://${V_CUSTOM_DOMAIN}"
      fi
    else
      V_CUSTOM_DOMAIN="${V_SERVER_IP_PUBLIC}"
      V_APP_URL="http://${V_CUSTOM_DOMAIN}"
    fi

    if [[ $(validate_domain_name "${V_CUSTOM_DOMAIN}") == true ]]; then
      if [[ $(host -4 "${V_CUSTOM_DOMAIN}" | awk 'NR==1 {print $NF}') != "${V_SERVER_IP_PUBLIC}" && 
        $(host "${V_CUSTOM_DOMAIN}" | awk 'NR==2 {print $NF}') != "${V_SERVER_IPV6_PUBLIC}" ]];
      then
        if [[ ${V_INPUT_RETRY} -lt 1 ]]; then
          echo ""
          echo "Your domain '${V_CUSTOM_DOMAIN}' is not pointing to this server."
          echo "To implement a custom domain in a production environment, "
          echo "You'll need to create an A and/or AAAA record in your DNS settings. "
          echo "This record should be pointed to the following IP addresses"
          echo "IPv4 Address (A): ${V_SERVER_IP_PUBLIC}"
          echo "IPv6 Address (AAAA): ${V_SERVER_IPV6_PUBLIC}"
          echo ""
        else
          echo "Retry checking DNS record for ${V_CUSTOM_DOMAIN}..."
        fi

        if [[ "${NONINTERACTIVE}" != y* && "${NONINTERACTIVE}" != Y* ]]; then
          read -t 600 -rp "Press [Enter] to retry or [Ctrl+C] to cancel..." </dev/tty
        else
          sleep 3 &
          wait # Wait for termination signal (ctrl+z / ctrl+c)
        fi

        # Retry checking DNS record (max. 10x retries)
        if [[ ${V_INPUT_RETRY} -lt 10 ]]; then
          return 1
        else
          echo -e "\nUnfortunately, we were unable to successfully install VitoDeploy \non your server using custom domain '${V_CUSTOM_DOMAIN}'."
          exit 1
        fi
      fi
    fi
  else
    V_CUSTOM_DOMAIN="localhost"
  fi

  return 0
}

# Make sure only root or sudo user can run this script
function check_root_access() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "This installer script must be run as root or with a sudo user."
    if [[ $(groups "$(id -un)" | grep -c sudo) -ne 0 ]]; then
      echo -e "\nFor a sudo user, you can run the following command:"
      echo "curl -sLO https://raw.githubusercontent.com/vitodeploy/vito/${VITO_VERSION}/scripts/install.sh && sudo ./install.sh"
    fi
    exit 1
  fi
}

# Check for supported OS
function check_supported_os() {
  OS_DISTRIB_NAME=${OS_DISTRIB_NAME:-$(lsb_release -is)}
  OS_RELEASE_NAME=${OS_RELEASE_NAME:-$(lsb_release -cs)}

  case "${OS_DISTRIB_NAME}" in
    "Ubuntu" | "ubuntu")
      DISTRIB_NAME="ubuntu"
      case "${OS_RELEASE_NAME}" in
        "noble" | "jammy" | "focal")
          RELEASE_NAME="${OS_RELEASE_NAME}"
        ;;
        *)
          RELEASE_NAME="unsupported"
        ;;
      esac
    ;;
    *)
      DISTRIB_NAME="unsupported"
    ;;
  esac

  if [[ "${DISTRIB_NAME}" == "unsupported" || "${RELEASE_NAME}" == "unsupported" ]]; then
    echo "This Linux distribution isn't supported yet."
    echo "If you'd like it to be, let us know!"
    echo "👉🏻 https://github.com/vitodeploy/vito/issues"
    exit 1
  fi
}

# Get server private IP Address
function get_ip_private() {
    local SERVER_IP_PRIVATE && \
    SERVER_IP_PRIVATE=$(ip addr | grep 'inet' | grep -v inet6 | \
        grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
        grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)

    echo "${SERVER_IP_PRIVATE}"
}

# Get server public IP Address
function get_ip_public() {
    local SERVER_IP_PRIVATE && SERVER_IP_PRIVATE=$(get_ip_private)
    local SERVER_IP_PUBLIC && \
    SERVER_IP_PUBLIC=$(curl -sk --ipv4 --connect-timeout 10 --retry 1 --retry-delay 0 https://freeipapi.com/api/json | tr -d '"' | awk -F "," '{print $2}' | awk -F "ipAddress:" '{print $2}')

    # Hack to detect public IP address behind NAT
    if [[ "${SERVER_IP_PRIVATE}" == "${SERVER_IP_PUBLIC}" ]]; then
        echo "${SERVER_IP_PRIVATE}"
    else
        echo "${SERVER_IP_PUBLIC}"
    fi
}

# Get server private IPv6 Address
function get_ipv6_private() {
    local SERVER_IPV6_PRIVATE && \
    SERVER_IPV6_PRIVATE=$(ip addr | grep 'inet6' | \
        grep -oE '(::)?[0-9a-fA-F]{1,4}(::?[0-9a-fA-F]{1,4}){1,7}(::)?' | head -1)

    echo "${SERVER_IPV6_PRIVATE}"
}

# Get server public IPv6 Address
function get_ipv6_public() {
    local SERVER_IPV6_PRIVATE && SERVER_IPV6_PRIVATE=$(get_ipv6_private)
    local SERVER_IPV6_PUBLIC && \
    #SERVER_IP_PUBLIC=$(curl -sk --ipv6 --connect-timeout 10 --retry 1 --retry-delay 0 https://freeipapi.com/api/json | tr -d '"' | awk -F "," '{print $2}' | awk -F "ipAddress:" '{print $2}')
    SERVER_IPV6_PUBLIC=$(curl -sk --ipv6 --connect-timeout 10 --retry 1 --retry-delay 0 https://ipecho.net/plain)

    # Hack to detect public IP address behind NAT
    if [[ "${SERVER_IPV6_PRIVATE}" == "${SERVER_IPV6_PUBLIC}" ]]; then
        echo "${SERVER_IPV6_PRIVATE}"
    else
        echo "${SERVER_IPV6_PUBLIC}"
    fi
}

# Validate domain name format
function validate_domain_name() {
  local DOMAIN_NAME=${1}

  if grep -qP "(?=^.{4,253}\.?$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)" <<< "${DOMAIN_NAME}"; then
    echo true
  else
    echo false
  fi
}

# Validate email address format
function validate_email_address() {
  local EMAIL_ADDRESS=${1}
  local EMAIL_REGEX="^(([A-Za-z0-9]+((\.|\-|\_|\+)?[A-Za-z0-9]?)*[A-Za-z0-9]+)|[A-Za-z0-9]+)@(([A-Za-z0-9]+)+((\.|\-|\_)?([A-Za-z0-9]+)+)*)+\.([A-Za-z]{2,})+$"

  if grep -qP "${EMAIL_REGEX}" <<< "${EMAIL_ADDRESS}"; then
    echo true
  else
    echo false
  fi
}

# Get physical RAM size
function get_ram_size() {
  local _RAM_SIZE
  local _RAM_UNIT
  local RAM_SIZE_IN_MB

  # Calculate RAM size in MB
  _RAM_SIZE=$(dmidecode -t 17 | awk '( /Size/ && $2 ~ /^[0-9]+$/ ) { print $2}')
  _RAM_UNIT=$(dmidecode -t 17 | awk '( /Size/ && $2 ~ /^[0-9]+$/ ) { print $3}')

  case "${_RAM_UNIT}" in
    "GB")
      RAM_SIZE_IN_MB=$((_RAM_SIZE * 1024))
    ;;
    *)
      RAM_SIZE_IN_MB=$((_RAM_SIZE * 1))
    ;;
  esac

  echo "${RAM_SIZE_IN_MB}"
}

# Create custom swap space
function create_swap() {
  local SWAP_FILE="/swapfile"
  local SWAP_SIZE=512
  local RAM_SIZE && RAM_SIZE=$(get_ram_size)

  if [[ ${RAM_SIZE} -le 2048 ]]; then
    SWAP_SIZE=$((RAM_SIZE * 2))
  elif [[ ${RAM_SIZE} -gt 2048 && ${RAM_SIZE} -le 32768 ]]; then
    SWAP_SIZE=$((4096 + (RAM_SIZE - 2048)))
  else
    SWAP_SIZE=$((RAM_SIZE * 1))
  fi

  echo "Creating ${SWAP_SIZE}MiB swap..."

  # Create swap space
  fallocate -l "${SWAP_SIZE}M" "${SWAP_FILE}" && \
  chmod 600 "${SWAP_FILE}" && \
  chown root:root "${SWAP_FILE}" && \
  mkswap "${SWAP_FILE}" && \
  swapon "${SWAP_FILE}"

  # Make swap space permanent
  if grep -qwE "#${SWAP_FILE}" /etc/fstab; then
    sed -i "s|#${SWAP_FILE}|${SWAP_FILE}|g" /etc/fstab
  else
    echo "${SWAP_FILE} swap swap defaults 0 0" >> /etc/fstab
    echo "Swap space created and enabled at '${SWAP_FILE}'"
  fi
}

# Upgrading OS & install prerequisites
function install_prerequisites() {
  echo -e "\nUpgrading OS and install prerequisites"

  # Create swap space for machine with low RAM
  echo "Detecting available swap space"
  if free | awk '/^Swap:/ {exit !$2}'; then
    local SWAP_SIZE && SWAP_SIZE=$(free -m | awk '/^Swap:/ { print $2 }')
    echo "Swap space size ${SWAP_SIZE}MiB"
  else
    echo "No swap space detected"
    create_swap
  fi

  # Upgrade OS
  echo "Updating operating system"
  apt remove needrestart -y
  apt clean && \
  apt update -qq -y --fix-missing && \
  apt upgrade -qq -y && \
  apt autoremove -q -y

  # Install requirements
  echo "Installing required dependencies"
  apt install -qq -y apt-transport-https apt-utils build-essential curl dnsutils git gcc net-tools software-properties-common sqlite3 unzip zip
}

# Install SQLite v3 latest
function install_sqlite3_from_source() {
  SQLITE_RELEASE_YEAR=${1:-"2024"} # 2024
  SQLITE_RELEASE_VERSION=${2:-"3460100"} # 3460100
  SQLITE_SOURCE_URL="https://www.sqlite.org/${SQLITE_RELEASE_YEAR}/sqlite-autoconf-${SQLITE_RELEASE_VERSION}.tar.gz"

  echo "Installing SQLite v3 from source"

  if curl -sLI "${SQLITE_SOURCE_URL}" | grep -q "HTTP/[.12]* [2].."; then
    curl -sSL -o "sqlite-autoconf-${SQLITE_RELEASE_VERSION}.tar.gz" "${SQLITE_SOURCE_URL}" && \
    tar -xzf "sqlite-autoconf-${SQLITE_RELEASE_VERSION}.tar.gz" && \
    cd "sqlite-autoconf-${SQLITE_RELEASE_VERSION}" && \
    apt -q -y install libreadline-dev && \
    CFLAGS="-O2 -DSQLITE_ENABLE_COLUMN_METADATA=1" ./configure && \
    make && make install && \
    ldconfig && \
    cd ../ || return 1
    rm -fr "sqlite-autoconf-${SQLITE_RELEASE_VERSION}"
    rm -f "sqlite-autoconf-${SQLITE_RELEASE_VERSION}.tar.gz"
    SQLITE_BIN=$(command -v sqlite3)
    [[ -x "${SQLITE_BIN}" ]] && "${SQLITE_BIN}" --version
  else
    echo "SQLite v3 source file could not be found"
  fi
}

# Vitodeploy installation
function vitodeploy_install() {
  echo -e "\nInstalling VitoDeploy, please sit tight..."

  install_prerequisites

  # Create system user account
  echo "Creating system user account for '${V_USERNAME}'"
  if [[ -z $(getent passwd "${V_USERNAME}") ]]; then
    HASHED_PASSWORD=$(openssl passwd -1 "${V_PASSWORD}")
    useradd -p "${HASHED_PASSWORD}" "${V_USERNAME}" && \
    usermod -aG sudo "${V_USERNAME}"
    touch /etc/sudoers.d/90-vito-users && \
    echo "${V_USERNAME} ALL=(ALL) NOPASSWD:ALL" | tee -a /etc/sudoers.d/90-vito-users
    mkdir "/home/${V_USERNAME}"
    mkdir "/home/${V_USERNAME}/.ssh"
    chown -R "${V_USERNAME}:${V_USERNAME}" "/home/${V_USERNAME}"
    chsh -s /bin/bash "${V_USERNAME}"
    su - "${V_USERNAME}" -c "ssh-keygen -t rsa -N '' -C '${V_ADMIN_EMAIL}' -f ~/.ssh/id_rsa" <<<y
    echo "User '${V_USERNAME}' created and added to sudo"
  else
    echo "System user account '${V_USERNAME}' already exists"
  fi

  # Python (required to install Certbot)
  echo "Installing Python (required for Certbot)"
  add-apt-repository ppa:deadsnakes/ppa -y && \
  apt update -qq -y && \
  apt install -qq -y python3.11 python3.11-dev python3.11-venv && \
  update-alternatives --install /usr/bin/python python "$(command -v python3.11)" 311 && \
  update-alternatives --set python /usr/bin/python3.11
  
  # Certbot
  echo "Installing Certbot Let's Encrypt client"
  python -m venv /opt/certbot/ && \
  /opt/certbot/bin/pip install --upgrade pip setuptools cffi && \
  /opt/certbot/bin/pip install --upgrade certbot certbot-nginx && \
  ln -sf /opt/certbot/bin/certbot /usr/bin/certbot
  if [[ -d /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory ]]; then
    certbot update_account --email "${V_ADMIN_EMAIL}" --no-eff-email --agree-tos
  else
    certbot register --email "${V_ADMIN_EMAIL}" --no-eff-email --agree-tos
  fi

  # Redis for caching and queue
  echo "Installing Redis key-value store database"
  if [[ ! -f "/etc/apt/sources.list.d/redis-${OS_RELEASE_NAME}.list" ]]; then
    bash -c "curl -fsSL https://packages.redis.io/gpg | gpg --dearmor --yes -o /usr/share/keyrings/redis-${OS_RELEASE_NAME}.gpg" && \
    chmod 644 "/usr/share/keyrings/redis-${OS_RELEASE_NAME}.gpg" && \
    touch "/etc/apt/sources.list.d/redis-${OS_RELEASE_NAME}.list" && \
    bash -c "echo 'deb [signed-by=/usr/share/keyrings/redis-${OS_RELEASE_NAME}.gpg] https://packages.redis.io/deb ${OS_RELEASE_NAME} main' | tee /etc/apt/sources.list.d/redis-${RELEASE_NAME}.list" && \
    apt update --allow-releaseinfo-change -q -y
  fi
  apt install -qq -y redis redis-server redis-tools && \
  systemctl enable redis-server.service && \
  systemctl restart redis-server.service

  # Nginx
  echo "Installing Nginx webserver"
  add-apt-repository ppa:ondrej/nginx -y && \
  apt update -qq -y && \
  apt install -qq -y nginx libnginx-mod-brotli libnginx-mod-http-cache-purge
  export V_NGINX_CONFIG="user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
  worker_connections 768;
}
http {
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 65;
  types_hash_max_size 2048;
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
  ssl_prefer_server_ciphers on;
  access_log /var/log/nginx/access.log;
  error_log /var/log/nginx/error.log;
  gzip on;
  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}
"
  if ! echo "${V_NGINX_CONFIG}" | tee /etc/nginx/nginx.conf; then
      echo "Can't configure nginx!" && exit 1
  fi
  service nginx start

  # PHP
  export V_PHP_VERSION="8.3"
  echo "Installing PHP ${V_PHP_VERSION} & extensions"
  add-apt-repository ppa:ondrej/php -y && \
  apt update -qq -y && \
  apt install -qq -y "php${V_PHP_VERSION}" "php${V_PHP_VERSION}-fpm" "php${V_PHP_VERSION}-mbstring" "php${V_PHP_VERSION}-mcrypt" \
    "php${V_PHP_VERSION}-gd" "php${V_PHP_VERSION}-xml" "php${V_PHP_VERSION}-curl" "php${V_PHP_VERSION}-gettext" "php${V_PHP_VERSION}-zip" \
    "php${V_PHP_VERSION}-bcmath" "php${V_PHP_VERSION}-soap" "php${V_PHP_VERSION}-redis" "php${V_PHP_VERSION}-sqlite3" \
    "php${V_PHP_VERSION}-ssh2" "php${V_PHP_VERSION}-intl"
  if [[ ! -f "/etc/php/${V_PHP_VERSION}/fpm/pool.d/www.conf" ]]; then
    echo "Error installing PHP ${V_PHP_VERSION}" && exit 1
  fi
  cp "/etc/php/${V_PHP_VERSION}/fpm/pool.d/www.conf" "/etc/php/${V_PHP_VERSION}/fpm/pool.d/www.conf.bak"
  mv "/etc/php/${V_PHP_VERSION}/fpm/pool.d/www.conf" "/etc/php/${V_PHP_VERSION}/fpm/pool.d/${V_USERNAME}.conf"
  sed -i "s/user\ =\ www-data/user\ =\ ${V_USERNAME}/g" "/etc/php/${V_PHP_VERSION}/fpm/pool.d/${V_USERNAME}.conf"
  sed -i "s/group\ =\ www-data/group\ =\ ${V_USERNAME}/g" "/etc/php/${V_PHP_VERSION}/fpm/pool.d/${V_USERNAME}.conf"
  sed -i "s/\[www\]/\[${V_USERNAME}\]/g" "/etc/php/${V_PHP_VERSION}/fpm/pool.d/${V_USERNAME}.conf"
  cp "/lib/systemd/system/php${V_PHP_VERSION}-fpm.service" "/lib/systemd/system/php${V_PHP_VERSION}-fpm.service.bak"
  systemctl enable "php${V_PHP_VERSION}-fpm"
  systemctl start "php${V_PHP_VERSION}-fpm"

  # Update SQLite v3 (latest)
  if command -v sqlite3; then
    if [[ $(sqlite3 --version | awk -F ' ' '{print $1}' | tr -d '.') -lt 3370 ]]; then
      install_sqlite3_from_source "2024" "3460100"
    fi
  else
    install_sqlite3_from_source "2024" "3460100"
  fi
  systemctl restart "php${V_PHP_VERSION}-fpm"

  # Composer
  curl -sS https://getcomposer.org/installer -o composer-setup.php
  php composer-setup.php --install-dir=/usr/local/bin --filename=composer
  rm -f composer-setup.php

  # Setup website
  echo "Setup VitoDeploy website"
  export COMPOSER_ALLOW_SUPERUSER=1
  export V_REPO="https://github.com/vitodeploy/vito.git"
  export V_VHOST_CONFIG="server {
  listen 80;
  listen [::]:80;
  http2 off;
  server_name _;

  #ssl_certificate /etc/letsencrypt/live/${V_CUSTOM_DOMAIN}/cert.pem;
  #ssl_certificate_key /etc/letsencrypt/live/${V_CUSTOM_DOMAIN}/privkey.pem;
  #ssl_trusted_certificate /etc/letsencrypt/live/${V_CUSTOM_DOMAIN}/fullchain.pem;

  add_header X-Frame-Options \"SAMEORIGIN\";
  add_header X-Content-Type-Options \"nosniff\";
  add_header X-XSS-Protection \"1; mode=block\" always;

  root /home/${V_USERNAME}/vito/public;
  index index.php;

  charset utf-8;

  location / {
    try_files \$uri \$uri/ /index.php?\$query_string;
  }

  location = /favicon.ico { access_log off; log_not_found off; }
  location = /robots.txt  { access_log off; log_not_found off; }

  error_page 404 /index.php;

  location ~ \.php$ {
    fastcgi_pass unix:/var/run/php/php${V_PHP_VERSION}-fpm.sock;
    fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
    include fastcgi_params;
    fastcgi_hide_header X-Powered-By;
  }

  location ~ /\.(?!well-known).* {
    deny all;
  }
}
"
  rm -rf "/home/${V_USERNAME}/vito"
  mkdir -p "/home/${V_USERNAME}/vito"
  chown -R "${V_USERNAME}:${V_USERNAME}" "/home/${V_USERNAME}/vito"
  chmod -R 755 "/home/${V_USERNAME}/vito"
  rm /etc/nginx/sites-available/default
  rm /etc/nginx/sites-enabled/default
  echo "${V_VHOST_CONFIG}" | tee /etc/nginx/sites-available/vito
  ln -s /etc/nginx/sites-available/vito /etc/nginx/sites-enabled/
  rm -rf "/home/${V_USERNAME}/vito"
  git config --global core.fileMode false
  git clone -b "${VITO_VERSION}" "${V_REPO}" "/home/${V_USERNAME}/vito"
  find "/home/${V_USERNAME}/vito" -type d -exec chmod 755 {} \;
  find "/home/${V_USERNAME}/vito" -type f -exec chmod 644 {} \;
  cd "/home/${V_USERNAME}/vito" && git config core.fileMode false
  cd "/home/${V_USERNAME}/vito" || exit 1
  # Check for the latest release tag
  if [[ $(git tag -l --sort=-v:refname | head -n 1 | awk -F '.' '{print $1}') -eq $(echo "${VITO_VERSION}" | awk -F '.' '{print $1}') ]]; then 
    V_GIT_BRANCH=$(git tag -l --merged "${VITO_VERSION}" --sort=-v:refname | head -n 1)
  else 
    V_GIT_BRANCH="${VITO_VERSION}" # If not available, fallback to the version branch
  fi
  git checkout "${V_GIT_BRANCH}"
  composer install --no-dev
  cp .env.prod .env
  sed -i "s|APP_URL=|APP_URL=${V_APP_URL}|g" .env
  V_ENV_CONFIG="
REDIS_CLIENT=phpredis
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

REDIS_QUEUE=redis #default
CACHE_DRIVER=redis #file
QUEUE_CONNECTION=redis #default
"
  echo "${V_ENV_CONFIG}" | tee -a .env
  touch "/home/${V_USERNAME}/vito/storage/database.sqlite"
  php artisan key:generate
  php artisan storage:link
  php artisan migrate --force
  php artisan user:create "${V_USERNAME}" "${V_ADMIN_EMAIL}" "${V_ADMIN_PASSWORD}"
  openssl genpkey -algorithm RSA -out "/home/${V_USERNAME}/vito/storage/ssh-private.pem"
  chmod 600 "/home/${V_USERNAME}/vito/storage/ssh-private.pem"
  ssh-keygen -y -C "${V_ADMIN_EMAIL}" -f "/home/${V_USERNAME}/vito/storage/ssh-private.pem" > "/home/${V_USERNAME}/vito/storage/ssh-public.key"
 
  # fix permission
  chown -hR "${V_USERNAME}:${V_USERNAME}" "/home/${V_USERNAME}"

  # optimize
  php artisan optimize
  php artisan icons:cache
  php artisan filament:optimize
  php artisan filament:cache-components

  # Setup custom domain + SSL
  if [[ "${V_APP_ENV}" == prod* && $(validate_domain_name "${V_CUSTOM_DOMAIN}") == true ]]; then
    sed -i "s/server_name\ _/server_name\ ${V_CUSTOM_DOMAIN}/g" /etc/nginx/sites-available/vito

    if [[ "${V_USE_HTTPS_DOMAIN}" == y* || "${V_USE_HTTPS_DOMAIN}" == Y* ]]; then
      if [[ -n $(command -v certbot) ]]; then
        certbot certonly --force-renewal --nginx --noninteractive --agree-tos \
          --cert-name "${V_CUSTOM_DOMAIN}" -m "${V_ADMIN_EMAIL}" -d "${V_CUSTOM_DOMAIN}" --verbose

        cp -f /etc/nginx/sites-available/vito /etc/nginx/sites-available/vito.nonssl

        if grep -qwE "^\    listen\ (\b[0-9]{1,3}\.){3}[0-9]{1,3}\b:80" /etc/nginx/sites-available/vito; then
          sed -i "s/\:80/\:443\ ssl/g" /etc/nginx/sites-available/vito
        fi
        sed -i "s/listen\ 80/listen\ 443\ ssl/g" /etc/nginx/sites-available/vito
        sed -i "s/listen\ \[::\]:80/listen\ \[::\]:443\ ssl/g" /etc/nginx/sites-available/vito
        sed -i "s/http2\ off/http2\ on/g" /etc/nginx/sites-available/vito
        sed -i "s/#ssl_certificate/ssl_certificate/g" /etc/nginx/sites-available/vito
        sed -i "s/#ssl_certificate_key/ssl_certificate_key/g" /etc/nginx/sites-available/vito
        sed -i "s/#ssl_trusted_certificate/ssl_trusted_certificate/g" /etc/nginx/sites-available/vito

        export V_HOST_CONFIG_HTTP_REDIRECT="## HTTP to HTTPS redirection.
server {
  listen 80;
  listen [::]:80;
  server_name ${V_CUSTOM_DOMAIN};

  location / {
    return 301 https://\$server_name\$request_uri;
  }
}
"
        echo "${V_HOST_CONFIG_HTTP_REDIRECT}" | tee -a /etc/nginx/sites-available/vito
      else
        echo "Certbot not found"
      fi
    fi
  fi
  service nginx reload -s

  # Setup supervisor
  export V_WORKER_CONFIG="[program:worker]
process_name=%(program_name)s_%(process_num)02d
command=php /home/${V_USERNAME}/vito/artisan queue:work --sleep=3 --backoff=0 --queue=default,ssh,ssh-long --timeout=3600 --tries=1
autostart=1
autorestart=1
user=${V_USERNAME}
redirect_stderr=true
stdout_logfile=/home/${V_USERNAME}/.logs/workers/worker.log
stopwaitsecs=3600
"
  apt install -qq -y supervisor && \
  service supervisor enable && \
  service supervisor start
  mkdir -p "/home/${V_USERNAME}/.logs"
  mkdir -p "/home/${V_USERNAME}/.logs/workers"
  touch "/home/${V_USERNAME}/.logs/workers/worker.log"
  echo "${V_WORKER_CONFIG}" | tee /etc/supervisor/conf.d/worker.conf
  supervisorctl reread
  supervisorctl update

  # setup cronjobs
  echo '0 */6 * * * /usr/bin/certbot renew --quiet --renew-hook "/usr/sbin/service nginx reload -s"' | crontab -
  echo "* * * * * cd /home/${V_USERNAME}/vito && php artisan schedule:run >> /dev/null 2>&1" | sudo -u "${V_USERNAME}" crontab -

  # start worker
  supervisorctl start worker:*
}

# Print info
function vitodeploy_print_info() {
  echo "🎉 Congratulations! Your VitoDeploy is ready."
  echo ""
  echo "🖥️  Here are your login credentials:"
  echo "✅ SSH User: ${V_USERNAME}"
  echo "✅ SSH Password: ${V_PASSWORD}"
  echo "✅ Admin Email: ${V_ADMIN_EMAIL}"
  echo "✅ Admin Password: ${V_ADMIN_PASSWORD}"
  echo "🌏 Admin Login Page: ${V_APP_URL}/login"
}

# Reset functions
function vitodeploy_reset() {
  unset -f vitodeploy_header check_root_access check_supported_os vitodeploy_input vitodeploy_install vitodeploy_print_info \
    vitodeploy_do_install terminate_cleanup vitodeploy_reset get_ip_private get_ip_prublic get_ipv6_private get_ipv6_prublic \
    validate_domain_name validate_email_address get_ram_size create_swap install_prerequisites install_sqlite3_from_source
}

# Handle termination signal
function vitodeploy_terminate_cleanup() {
  echo ""
  kill -term $$
  exit 0
}

function vitodeploy_do_install() {
  export VITO_VERSION="2.x"
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  export OS_DISTRIB_NAME && OS_DISTRIB_NAME=$(lsb_release -is)
  export OS_RELEASE_NAME && OS_RELEASE_NAME=$(lsb_release -cs)

  # Trap termination signal
  trap vitodeploy_terminate_cleanup SIGTSTP
  trap vitodeploy_terminate_cleanup SIGINT

  vitodeploy_header
  check_root_access "$@"
  check_supported_os
  echo "Starting VitoDeploy installation..."
  echo -e "Please ensure that you're on a fresh Ubuntu install!\n"
  if [[ "${NONINTERACTIVE}" != y* && "${NONINTERACTIVE}" != Y* ]]; then
    read -t 600 -rp "Press [Enter] to continue or [Ctrl+C] to cancel..." </dev/tty
  else
    sleep 2 & 
    wait # Wait for termination signal (ctrl+z / ctrl+c)
  fi
  vitodeploy_header
  echo -e "Please, enter required information below!\n"
  export V_INPUT_RETRY=0
  until vitodeploy_input
  do
    ((V_INPUT_RETRY++))
  done
  vitodeploy_install
  vitodeploy_header
  vitodeploy_print_info
  vitodeploy_reset
}

# Start VitoDeploy installation
vitodeploy_do_install "$@"

} # This ensures the entire script is downloaded #
