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

### `/etc/mysql_monitor/user_limits`
```
user_name soft_limit_bytes hard_limit_bytes

alice 1000000000 2000000000
bob 5000000000 8000000000
testuser 0 3000000000
```

### `/root/etc/mysql_monitor/passwd`
example_pass

---

## Installation

### Build Audit Plugin
```bash
gcc -fPIC -shared -o mysql_monitor_audit.so mysql_monitor_audit.c \
    $(mysql_config --cflags) $(mysql_config --libs) -lpthread
```

### Build Daemon
```bash
gcc -o mysql_monitor_daemon mysql_monitor_daemon.c \
    $(mysql_config --cflags) $(mysql_config --libs) -lpthread
```

### Systemd Service Example
/etc/systemd/system/mysql_monitor_daemon.service:
```
[Unit]
Description=MySQL User Storage Monitor Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/mysql_monitor_daemon
Restart=always
User=mysqlmon
Group=mysqlmon

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable mysql_monitor_daemon
systemctl start mysql_monitor_daemon
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

