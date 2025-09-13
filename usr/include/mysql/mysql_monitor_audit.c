/*
 * mysql_monitor_audit.c
 *
 * MySQL Audit Plugin for immediate user lock on storage overuse
 * - Supports MySQL 5.7 and 8.0
 * - Hooks INSERT/UPDATE/LOAD (GENERAL) and ALTER (DDL)
 * - Soft/Hard limit control
 * - Reads user limits from /etc/mysql_search/search_user
 * - Reads DB credentials from /root/etc/mysql_monitor/passwd
 *
 * Compile:
 *   gcc -fPIC -Wall -I/usr/include/mysql -shared -o mysql_monitor_audit.so mysql_monitor_audit.c -lmysqlclient
 *
 * Deploy:
 *   INSTALL PLUGIN mysql_monitor_audit SONAME 'mysql_monitor_audit.so';
 */

#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <mysql/mysql.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
static char g_db_user[64] = "root";
static char g_db_pass[128] = "";

// Load user limits from config
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

// Load DB password from file
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

// Search user limits
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

// Lock user if usage exceeded
static void lock_user_if_needed(MYSQL *conn, const char *user, long long usage) {
    long long soft, hard;
    if (get_limits(user, &soft, &hard) == 0) {
        if (soft > 0 && usage > soft) {
            syslog(LOG_WARNING, "[AuditPlugin] User %s exceeded soft limit (%lld).", user, usage);
        }
        if (hard > 0 && usage > hard) {
            char sql[256];
            snprintf(sql, sizeof(sql), "ALTER USER '%s'@'%%' ACCOUNT LOCK;", user);
            if (mysql_query(conn, sql) == 0) {
                syslog(LOG_INFO, "[AuditPlugin] LOCKED user %s (usage=%lld, hard=%lld)", user, usage, hard);
            } else {
                syslog(LOG_ERR, "[AuditPlugin] Failed to lock user %s: %s", user, mysql_error(conn));
            }
        }
    }
}

// Check usage via schema_privileges
static void check_user_usage(const char *user) {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) return;
    if (!mysql_real_connect(conn, "localhost", g_db_user, g_db_pass, NULL, 0, NULL, 0)) {
        mysql_close(conn);
        return;
    }

    char grantee[256];
    snprintf(grantee, sizeof(grantee), "'%s'@'%s'", user, "%");

    char sql[512];
    snprintf(sql, sizeof(sql),
        "SELECT SUM(DATA_LENGTH+INDEX_LENGTH) "
        "FROM information_schema.tables "
        "WHERE TABLE_SCHEMA IN ("
        "  SELECT DISTINCT TABLE_SCHEMA "
        "  FROM information_schema.schema_privileges "
        "  WHERE GRANTEE = %s"
        ");",
        grantee);

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

    mysql_close(conn);
}

// Audit callback
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
    }
    else if (event_class == MYSQL_AUDIT_DDL_COMMAND_CLASS) {
        const struct mysql_event_command *ev = (const struct mysql_event_command *)event;
        const char *user = ev->user;
        const char *cmd  = ev->name;
        if (!user || !cmd) return 0;

        if (strncasecmp(cmd, "ALTER", 5) == 0) {
            check_user_usage(user);
        }
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
    "Audit + Capacity Monitor Integration (5.7 & 8.0)",
    PLUGIN_LICENSE_GPL,
    load_user_limits,   /* Init */
    NULL,               /* Deinit */
    0x0100,
    NULL, NULL, NULL,
}
mysql_declare_plugin_end;
