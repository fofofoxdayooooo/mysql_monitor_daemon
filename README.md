# mysql_monitor_daemon

A powerful MySQL user storage monitoring daemon for Linux/FreeBSD environments.  
Designed for shared servers, internal DB clusters, and hosting environments where **automatic control of user overuse is mission-critical**.

## Features

- Secure privilege drop (runs as root, drops to `mysql`)
- Prometheus-compatible metrics output
- LRU cache for 1,000+ user limits with eviction
- Sharding support (e.g., 4-daemon horizontal scaling)
- Soft / Hard user quota enforcement
- Multi-threaded with task queue (configurable)
- Efficient `information_schema` based usage scan
- Clean `daemonize()` support
- SIGHUP-triggered config reload (no restart needed)

## File Structure
```
/etc/mysql_search/
├── search.conf # DB connection and interval config
├── passwd # MySQL passwords (0600 perms required)
└── search_user # User limits list: user,soft,hard
```

```
/root/mysql_search/
└── passwd # MySQL passwords (0600 perms required)
```

## Metrics Output

Writes Prometheus metrics to:

/var/run/mysql_monitor.prom


Supports:
- `mysql_user_storage_bytes`
- `mysql_user_storage_soft_limit_bytes`
- `mysql_user_storage_hard_limit_bytes`

## Initial Setup
```
# Place executable binary
install -m 755 mysql_monitor_daemon /usr/local/sbin/

# Create directories
mkdir -p /etc/mysql_search
mkdir -p /root/mysql_search
touch /etc/mysql_search/search.conf
touch /etc/mysql_search/search_user
touch /root/mysql_search/passwd

# Force Permissions (Very Important)
chmod 600 /etc/mysql_search/search.conf
chmod 600 /root/mysql_search/passwd
chmod 644 /etc/mysql_search/search_user

# Log file (OK to skip on first run)
touch /var/log/mysql_monitor_audit.log
chmod 640 /var/log/mysql_monitor_audit.log
```

## How It Works

1. Reads DB list and user quota settings
2. Connects to each DB and checks storage usage via:
 ```sql
SELECT TABLE_SCHEMA, SUM(DATA_LENGTH + INDEX_LENGTH) FROM information_schema.tables GROUP BY TABLE_SCHEMA;
 ```

3. If usage exceeds limits:
Logs warning to syslog and audit log
On hard-limit: disables account with:
```bash
ALTER USER 'user'@'%' ACCOUNT LOCK;
```

### Configuration
Example: search_user
```
user1,2GB,3GB
user2,500MB
```

Example: search.conf
```
db_host=127.0.0.1
db_user=root
db_id=0
monitor_interval_sec=600
prometheus_truncate=1
```

Example: /root/mysql_search/passwd
```
s3cr3tPassw0rd
```

### Step 1: Build the Plugin
```
# Save the source code
vi mysql_monitor_audit.c
```

Build (MySQL development headers required)
```
gcc -fPIC -Wall -I/usr/include/mysql -shared \
    -o mysql_monitor_audit.so mysql_monitor_audit.c -lmysqlclient
```
※ libmysqlclient-dev (Debian/Ubuntu) or mysql-devel (RHEL/CentOS) package is required.

### Step 2: Plugin Placement
```
# Verify MySQL's plugin directory
mysql -u root -p -e “SHOW VARIABLES LIKE ‘plugin_dir’;”
```

Example: /usr/lib64/mysql/plugin/
```
cp mysql_monitor_audit.so /usr/lib64/mysql/plugin/
chmod 644 /usr/lib64/mysql/plugin/mysql_monitor_audit.so
```
### Step 3: Create Dedicated User (Execute as root)
```
mysql -u root -p <<‘EOSQL’
CREATE USER ‘monitor_audit’@'localhost' IDENTIFIED BY ‘StrongPasswordHere’;
GRANT SELECT ON `information_schema`.`tables` TO ‘monitor_audit’@'localhost';
GRANT SELECT ON `information_schema`.`schema_privileges` TO ‘monitor_audit’@'localhost';
GRANT ALTER USER ON *.* TO ‘monitor_audit’@'localhost';
FLUSH PRIVILEGES;
EOSQL
```

### Step 4: Register the Plugin with MySQL
```
# Log in to MySQL
mysql -u root -p

# Register the plugin
INSTALL PLUGIN mysql_monitor_audit SONAME ‘mysql_monitor_audit.so’;

# Verify registration
SHOW PLUGINS LIKE ‘mysql_monitor_audit’;

Create MySQL user
```

```
-- Create a dedicated monitoring user (host restricted to local only)
CREATE USER ‘monitor_audit’@'localhost' IDENTIFIED BY ‘StrongPasswordHere’;

-- Permissions to retrieve capacity information from information_schema
GRANT SELECT ON `information_schema`.`tables` TO ‘monitor_audit’@'localhost';
GRANT SELECT ON `information_schema`.`schema_privileges` TO ‘monitor_audit’@'localhost';

-- Permissions required to LOCK/UNLOCK users
GRANT ALTER USER ON *.* TO ‘monitor_audit’@'localhost';

-- Do not grant other permissions to avoid unnecessary privileges
-- (CREATE, DROP, SUPER, GRANT OPTION, etc. are prohibited)

-- Refresh privileges
FLUSH PRIVILEGES;
```

### Main Build
```
gcc -O2 -Wall -o mysql_monitor_daemon mysql_monitor_daemon.c -lmysqlclient -lpthread
```

### service
/etc/systemd/system/mysql_monitor_daemon.service
```
[Unit]
Description=MySQL Connection Monitor Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/mysql_monitor_daemon -s %i
User=root
Group=root

# Security hardening settings
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_RESOURCE
PrivateDevices=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallFilter=~@mount @swap @reboot @keyring @cpu-hotplug

# Reload the daemon when SIGHUP is received
ExecReload=/bin/kill -HUP $MAINPID

# Allow the daemon to write to the Prometheus metrics file
ReadWritePaths=/var/run/mysql_monitor.prom
Restart=on-failure
RestartSec=5s
```

[Install]
WantedBy=multi-user.target

### Run
```bash
# Apply unit file changes
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

# Enable automatic startup
sudo systemctl enable mysql_monitor.service

# Start the service
sudo systemctl start mysql_monitor.service

# Check status
sudo systemctl status mysql_monitor.service
```
-d: debug level (0=log only, 2=lock)
-s: shard number (0-based)
-t: total shards

### License

MIT

### Author

abe_yamagami

a
