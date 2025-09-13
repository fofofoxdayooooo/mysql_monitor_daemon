/*
 * mysql_monitor_audit.c
 *
 * MySQL/MariaDB Audit Plugin for immediate user lock on storage overuse
 * - MySQL 5.7 / 8.0 supported
 * - MariaDB 10.3 and 10.4+ supported (different LOCK mechanism)
 * - Hooks INSERT/UPDATE/LOAD (GENERAL) and ALL DDL commands
 * - Soft/Hard limit control
 * - Reads user limits from /etc/mysql_search/search_user
 * - Reads DB credentials from /root/etc/mysql_monitor/passwd
 */

#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <mysql/mysql.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define MAX_USERS 1024

typedef struct {
    char user[64];
    long long soft_limit;
    long long hard_limit;
} UserLimit;

static UserLimit limits[MAX_USERS];
static int limit_count = 0;
static pthread_mutex_t limits_mutex = PTHREAD_MUTEX_INITIALIZER;

// DB connection info
static char g_db_user[64] = "monitor_audit";
static char g_db_pass[128] = "";

// A simple connection pool
#define POOL_SIZE 4
static MYSQL* g_connections[POOL_SIZE] = {NULL};
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to get a connection from the pool
static MYSQL* get_connection() {
    pthread_mutex_lock(&g_conn_mutex);
    for (int i = 0; i < POOL_SIZE; i++) {
        if (g_connections[i] != NULL) {
            MYSQL* conn = g_connections[i];
            g_connections[i] = NULL;
            pthread_mutex_unlock(&g_conn_mutex);
            return conn;
        }
    }
    pthread_mutex_unlock(&g_conn_mutex);

    // If pool is empty, create a new connection
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        syslog(LOG_ERR, "[AuditPlugin] Failed to initialize MySQL connection.");
        return NULL;
    }
    if (!mysql_real_connect(conn, "localhost", g_db_user, g_db_pass, NULL, 0, NULL, 0)) {
        syslog(LOG_ERR, "[AuditPlugin] Failed to connect to MySQL: %s", mysql_error(conn));
        mysql_close(conn);
        return NULL;
    }
    return conn;
}

// Function to return a connection to the pool
static void release_connection(MYSQL* conn) {
    if (!conn) return;
    pthread_mutex_lock(&g_conn_mutex);
    for (int i = 0; i < POOL_SIZE; i++) {
        if (g_connections[i] == NULL) {
            g_connections[i] = conn;
            pthread_mutex_unlock(&g_conn_mutex);
            return;
        }
    }
    // Pool is full, close the connection
    pthread_mutex_unlock(&g_conn_mutex);
    mysql_close(conn);
}

// Load user limits
static void load_user_limits() {
    FILE *fp = fopen("/etc/mysql_search/search_user", "r");
    if (!fp) {
        syslog(LOG_ERR, "[AuditPlugin] Failed to open search_user file.");
        return;
    }
    char line[256];
    pthread_mutex_lock(&limits_mutex);
    limit_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char name[64], soft_s[32], hard_s[32];
        if (sscanf(line, "%63s %31s %31s", name, soft_s, hard_s) == 3) {
            UserLimit ul;
            strncpy(ul.user, name, sizeof(ul.user));
            ul.soft_limit = atoll(soft_s);
            ul.hard_limit = atoll(hard_s);
            if (limit_count < MAX_USERS) {
                limits[limit_count++] = ul;
            }
        }
    }
    pthread_mutex_unlock(&limits_mutex);
    fclose(fp);
}

// Load DB password
static void load_password() {
    FILE *fp = fopen("/root/etc/mysql_monitor/passwd", "r");
    if (!fp) {
        syslog(LOG_ERR, "[AuditPlugin] Failed to open passwd file.");
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char user[64], pass[128];
        if (sscanf(line, "%63s %127s", user, pass) == 2) {
            if (strcmp(user, g_db_user) == 0) {
                strncpy(g_db_pass, pass, sizeof(g_db_pass));
                break;
            }
        }
    }
    fclose(fp);
}

// Search limits
static int get_limits(const char *user, long long *soft, long long *hard) {
    pthread_mutex_lock(&limits_mutex);
    for (int i = 0; i < limit_count; i++) {
        if (strcmp(limits[i].user, user) == 0) {
            *soft = limits[i].soft_limit;
            *hard = limits[i].hard_limit;
            pthread_mutex_unlock(&limits_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&limits_mutex);
    return -1;
}

// Version check for MariaDB 10.4+
static bool is_mariadb_104_or_higher(MYSQL *conn) {
    if (mysql_query(conn, "SELECT VERSION()") != 0) return false;
    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) return false;
    MYSQL_ROW row = mysql_fetch_row(res);
    bool ret = false;
    if (row && row[0]) {
        if (strstr(row[0], "MariaDB")) {
            int major, minor;
            if (sscanf(row[0], "%*[^0-9]%d.%d", &major, &minor) == 2) {
                if (major > 10 || (major == 10 && minor >= 4)) {
                    ret = true;
                }
            }
        }
    }
    mysql_free_result(res);
    return ret;
}

// Lock user if exceeded
static void lock_user_if_needed(MYSQL *conn, const char *user, long long usage) {
    long long soft, hard;
    if (get_limits(user, &soft, &hard) == 0) {
        if (soft > 0 && usage > soft) {
            syslog(LOG_WARNING, "[AuditPlugin] User %s exceeded soft limit (%lld).", user, usage);
        }
        if (hard > 0 && usage > hard) {
            bool is_mariadb = strstr(mysql_get_server_info(conn), "MariaDB") != NULL;
            char sql[256];
            
            if (is_mariadb && is_mariadb_104_or_higher(conn)) {
                snprintf(sql, sizeof(sql), "ALTER USER '%s'@'%%' ACCOUNT LOCK;", user);
                if (mysql_query(conn, sql) == 0) {
                    syslog(LOG_INFO, "[AuditPlugin] LOCKED user %s (MariaDB>=10.4, usage=%lld)", user, usage);
                }
            } else {
                // Fallback for MySQL and older MariaDB
                snprintf(sql, sizeof(sql), "UPDATE mysql.user SET account_locked='Y' WHERE user='%s';", user);
                char sql2[64];
                snprintf(sql2, sizeof(sql2), "FLUSH PRIVILEGES;");
                if (mysql_query(conn, sql) == 0 && mysql_query(conn, sql2) == 0) {
                    syslog(LOG_INFO, "[AuditPlugin] LOCKED user %s (older version, usage=%lld)", user, usage);
                }
            }
        }
    }
}

// Check usage
static void check_user_usage(const char *user) {
    MYSQL *conn = get_connection();
    if (!conn) return;

    char grantee_user[64];
    char grantee_host[64];
    const char *at_sign = strchr(user, '@');
    if (at_sign) {
        strncpy(grantee_user, user, at_sign - user);
        grantee_user[at_sign - user] = '\0';
        strcpy(grantee_host, at_sign + 1);
    } else {
        strcpy(grantee_user, user);
        strcpy(grantee_host, "localhost");
    }

    char sql[768];
    snprintf(sql, sizeof(sql),
        "SELECT SUM(DATA_LENGTH+INDEX_LENGTH) "
        "FROM information_schema.tables "
        "WHERE TABLE_SCHEMA IN ("
        "  SELECT DISTINCT table_schema "
        "  FROM information_schema.schema_privileges "
        "  WHERE GRANTEE IN ('%s@%s', '%s@%%') "
        ");",
        grantee_user, grantee_host, grantee_user);

    if (mysql_query(conn, sql) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) {
                long long usage = atoll(row[0]);
                lock_user_if_needed(conn, user, usage);
            }
            mysql_free_result(res);
        }
    } else {
        syslog(LOG_ERR, "[AuditPlugin] SQL error while checking user %s: %s",
               user, mysql_error(conn));
    }
    
    release_connection(conn);
}

// Audit notify
static int audit_notify(MYSQL_THD thd, unsigned int event_class, const void *event) {
    if (event_class == MYSQL_AUDIT_GENERAL_CLASS) {
        const struct mysql_event_general *ev = (const struct mysql_event_general *)event;
        const char *user = ev->user;
        const char *cmd  = ev->general_query;
        if (!user || !cmd) return 0;
        if (strncasecmp(cmd, "INSERT ", 7) == 0 ||
            strncasecmp(cmd, "UPDATE ", 7) == 0 ||
            strncasecmp(cmd, "LOAD ",   5) == 0) {
            check_user_usage(user);
        }
    } else if (event_class == MYSQL_AUDIT_DDL_COMMAND_CLASS) {
        const struct mysql_event_ddl *ev = (const struct mysql_event_ddl *)event;
        const char *user = ev->user;
        const char *cmd  = ev->ddl_query;
        if (!user || !cmd) return 0;
        check_user_usage(user);
    }
    return 0;
}

// Plugin interface
static struct st_mysql_audit audit_interface = {
    MYSQL_AUDIT_INTERFACE_VERSION,
    NULL,
    audit_notify,
    { 1, 0, 0, 1, 1, 0, 0, 0 } // connection + general + ddl
};

mysql_declare_plugin(mysql_monitor_audit) {
    MYSQL_AUDIT_PLUGIN,
    &audit_interface,
    "mysql_monitor_audit",
    "YourName",
    "Audit + Capacity Monitor Integration (MySQL/MariaDB)",
    PLUGIN_LICENSE_GPL,
    load_user_limits,   /* Init */
    NULL,               /* Deinit */
    0x0100,
    NULL, NULL, NULL,
}
mysql_declare_plugin_end;
