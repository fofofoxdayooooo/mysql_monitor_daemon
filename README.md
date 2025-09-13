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

/etc/mysql_search/
├── search.conf # DB connection and interval config
├── passwd # MySQL passwords (0600 perms required)
└── search_user # User limits list: user,soft,hard

## Metrics Output

Writes Prometheus metrics to:

/var/run/mysql_monitor.prom


Supports:
- `mysql_user_storage_bytes`
- `mysql_user_storage_soft_limit_bytes`
- `mysql_user_storage_hard_limit_bytes`

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

Configuration
Example: search_user
user1,2GB,3GB
user2,500MB

Example: search.conf
db_host=127.0.0.1
db_user=root
db_id=0
monitor_interval_sec=3600

Example: /root/etc/mysql_monitor/passwd
```
s3cr3tPassw0rd
```

Build
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
sudo ./mysql_monitor_daemon -d 2 -s 0 -t 1
```
-d: debug level (0=log only, 2=lock)
-s: shard number (0-based)
-t: total shards

### License

MIT

### Author

abe_yamagami





abe_yamagami
a
