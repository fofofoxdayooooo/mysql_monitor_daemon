# MySQL / MariaDB User Storage Monitor

A **MySQL / MariaDB monitoring solution** to prevent resource abuse in shared environments.  
This project contains two main components:

1. **Audit Plugin (`mysql_monitor_audit.c`)**  
   - Hooks into MySQL/MariaDB via the Audit API.  
   - Monitors `INSERT`, `UPDATE`, `LOAD`, and all DDL queries.  
   - Checks user storage usage in real time and locks accounts exceeding hard limits.  
   - Supports both MySQL (5.7 / 8.0) and MariaDB (10.3 / 10.4+).

2. **Standalone Daemon (`mysql_monitor_daemon.c`)**  
   - Runs as a background process on Linux / FreeBSD.  
   - Periodically queries storage usage for each user.  
   - Uses **LRU caching** for performance and writes **Prometheus metrics** for Grafana dashboards.  
   - Supports **soft limits** (syslog warning) and **hard limits** (automatic account lock).  
   - Compatible with both MySQL and MariaDB, including older versions.  
   - Reloads configuration on **SIGHUP** without restart.

3. **Lastkill daemon(`storage_guard storage_guard.c`)**
- Cross-platform daemon (Linux / FreeBSD)
- INI-style configuration (`/etc/storage_guard.conf`)
- User limits inline (`[limits]`) or in a separate `[users]` file
- DB version detection (MySQL / MariaDB legacy/new)
- Soft / Hard limit detection with:
  - **Soft limit:** warning only
  - **Hard limit:** `LOCK USER` + `KILL SESSION`
- Configurable `threshold_trigger` before action
- Thread pool implementation for efficient parallel checks
- Connection pooling support (`use_connection_pool`)
- Prometheus metrics output with extended labels (`db_type`, `host`, etc.)
- Log level control (DEBUG/INFO/WARN/ERROR)
- `--dry-run` mode for safe testing
- `SIGHUP` reloads configuration without restart
- Daemon privilege drop (`daemon_user`, `daemon_group`)
  
---

## Features

- Real-time and periodic monitoring
- Per-user soft/hard limits
- Automatic account locking (MySQL/MariaDB-aware)
- Prometheus metrics exporter
- Configurable via external files
- Multi-threaded with task queue
- Safe **atomic metrics writes**
- Runs on **Linux and FreeBSD**
---

## File Layout

```bash
/etc/
└──storage_guard.conf

/etc/mysql_monitor/
├── db_config # Daemon DB connection list
├── user_limits # User limits definition
├── config # Plugin config (hostname, port, socket)
└── passwd # Password file (mode 600)
```

## /var/run/mysql_monitor.prom # Prometheus metrics output

## Example Configurations

### `/etc/mysql_monitor/db_config`
```
hostname username password database port interval query_method

127.0.0.1 monitor_user example_pass mysql 3306 60 information_schema
192.168.1.10 monitor_user another_pass mysql 3306 120 sys_schema
```
```bash
chmod 600 /etc/mysql_monitor/db_config
chown root:root /etc/mysql_monitor/db_config
```

### `/etc/mysql_monitor/user_limits`
```
user_name soft_limit_bytes hard_limit_bytes

alice 1000000000 2000000000
bob 5000000000 8000000000
testuser 0 3000000000
```

### `/root/etc/mysql_monitor/passwd`
example_pass

### `/etc/storage_guard.conf`
```bash
[general]
log_level = INFO
check_interval = 30
metrics_file = /var/run/storage_guard.prom
kill_on_hard_limit = yes
user_limits_file = /etc/storage_guard_users.conf
threshold_trigger = 3
use_threads = yes
max_threads = 16
use_connection_pool = yes
connection_pool_size = 10
daemon_user = mysqlmon
daemon_group = mysqlmon

[database]
host = localhost
port = 3306
user = monitor
password_file = /root/etc/mysql_monitor/passwd
type = mysql

[limits]
user1 = 500000000 , 1000000000
user2 = 1000000000 , 2000000000
```
User limits can also be kept in a separate file defined by user_limits_file.

---

## Installation

### Build Audit Plugin
```bash
RHEL
gcc -O2 -Wall -o mysql_monitor_audit mysql_monitor_audit.c \
    -lmysqlclient -lpthread

Debian/Ubuntu
sudo apt-get install build-essential libmysqlclient-dev
gcc -O2 -Wall -o mysql_monitor_audit mysql_monitor_audit.c \
    -lmysqlclient -lpthread

BSD
pkg install mysql80-client
cc -O2 -Wall -pthread -o mysql_monitor_audit mysql_monitor_audit.c \
   -lmysqlclient
```

### Build Daemon
```bash
RHEL
sudo yum install gcc mysql-devel
gcc -O2 -Wall -o mysql_monitor_daemon mysql_monitor_daemon.c \
    -lmysqlclient -lpthread

Debian/Ubuntu
sudo apt-get install build-essential libmysqlclient-dev
gcc -O2 -Wall -o mysql_monitor_daemon mysql_monitor_daemon.c \
    -lmysqlclient -lpthread

BSD
pkg install mysql80-client
cc -O2 -Wall -pthread -o mysql_monitor_daemon mysql_monitor_daemon.c \
   -lmysqlclient
```

### Build Last Daemon
```bash
RHEL
sudo yum install gcc mysql-devel
gcc -O2 -Wall -o storage_guard storage_guard.c \
    -lmysqlclient -lpthread

Debian/Ubuntu
sudo apt-get install build-essential libmysqlclient-dev
gcc -O2 -Wall -o storage_guard storage_guard.c \
    -lmysqlclient -lpthread

BSD
pkg install mysql80-client
cc -O2 -Wall -o storage_guard storage_guard.c \
   -lmysqlclient -lutil -lpthread
```

### Systemd Service Example
/etc/systemd/system/mysql_monitor_daemon.service:
```
[Unit]
Description=MySQL User Storage Monitor Daemon
After=network.target

[Service]
ExecStart=/usr/local/mysql_monitor_daemon/bin/mysql_monitor_daemon
Restart=always
User=mysqlmon
Group=mysqlmon

[Install]
WantedBy=multi-user.target
```

/etc/systemd/system/storage_guard.service:
```bash
[Unit]
Description=Storage Guard Daemon for MySQL/MariaDB
After=network.target mysqld.service mariadb.service

[Service]
Type=simple
ExecStart=/usr/local/mysql_monitor_daemon/bin/storage_guard
Restart=always
RestartSec=5s
User=mysqlmon
Group=mysqlmon
RuntimeDirectory=storage_guard
PIDFile=/var/run/storage_guard.pid
LimitNOFILE=65535

# Ensure only the dedicated user can read configs
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

```

```bash
systemctl daemon-reload
systemctl enable mysql_monitor_daemon
systemctl start mysql_monitor_daemon
systemctl enable storage_guard
systemctl start storage_guard
systemctl status storage_guard
```

### Prometheus Integration
Metrics are written to /var/run/mysql_monitor.prom in textfile format.
Example output:
```bash
# HELP mysql_user_storage_usage_bytes Current storage usage for a user in bytes.
# TYPE mysql_user_storage_usage_bytes gauge
mysql_user_storage_usage_bytes{user="alice", limit_type="current"} 123456789
mysql_user_storage_usage_bytes{user="alice", limit_type="soft"} 1000000000
mysql_user_storage_usage_bytes{user="alice", limit_type="hard"} 2000000000
```

### Minimum Privileges for Monitor User
```bash
CREATE USER 'monitor_user'@'%' IDENTIFIED BY 'example_pass';
GRANT SELECT ON `information_schema`.* TO 'monitor_user'@'%';
GRANT SELECT ON `mysql`.* TO 'monitor_user'@'%';
GRANT PROCESS ON *.* TO 'monitor_user'@'%';
```
### License

MIT License

### Disclaimer

This software is intended for hosting providers, DBAs, and sysadmins
to prevent resource abuse in shared MySQL/MariaDB environments.
Use with caution in production and always test in staging first.


## File Layout

