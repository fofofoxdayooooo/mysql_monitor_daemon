/*
 * mysql_monitor_audit.c
 *
 * MySQL/MariaDB Audit Plugin for immediate user lock on storage overuse
 * - MySQL 5.7 / 8.0 supported
 * - MariaDB 10.3 and 10.4+ supported (different LOCK mechanism)
 * - Hooks INSERT/UPDATE/LOAD (GENERAL) and ALL DDL commands
 * - Soft/Hard limit control
 * - Reads user limits from /etc/mysql_monitor/user_limits
 * - Reads DB credentials from /root/etc/mysql_monitor/passwd
 * - Reads DB connection info (hostname/port/socket) from /etc/mysql_monitor/config
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
#include <errno.h>

#define MAX_USERS 1024
#define PASSWD_FILE "/root/etc/mysql_monitor/passwd"
#define USER_LIMITS_FILE "/etc/mysql_monitor/user_limits"
#define CONFIG_FILE "/etc/mysql_monitor/config"

typedef struct {
    char user[64];
    long long soft_limit;
    long long hard_limit;
} UserLimit;

static UserLimit limits[MAX_USERS];
static int limit_count = 0;
static pthread_mutex_t limits_mutex = PTHREAD_MUTEX_INITIALIZER;

// DB connection info
static char g_db_hostname[256] = "localhost";
static unsigned int g_db_port = 3306;       // default MySQL port
static char g_db_socket[256] = "";          // optional socket
static char g_db_user[64] = "monitor_audit";
static char g_db_password[128] = "";

// Function prototypes
static int read_db_pass();
static int read_user_limits();
static int read_config();
static long long check_user_storage(const char *user);
static void *check_user_usage_worker(void *arg);
static void lock_user_account(const char *user);
static int audit_notify(MYSQL_AUDIT_INFO *audit_info, unsigned int event_class, const void *event);

static int read_config() {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_WARNING, "Failed to open config file %s: %s. Using defaults.", CONFIG_FILE, strerror(errno));
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char key[128], value[384];
        if (sscanf(line, "%127[^=]=%383s", key, value) == 2) {
            if (strcmp(key, "hostname") == 0) {
                strncpy(g_db_hostname, value, sizeof(g_db_hostname) - 1);
                g_db_hostname[sizeof(g_db_hostname) - 1] = '\0';
                syslog(LOG_INFO, "Configured DB hostname: %s", g_db_hostname);
            } else if (strcmp(key, "port") == 0) {
                g_db_port = (unsigned int)atoi(value);
                syslog(LOG_INFO, "Configured DB port: %u", g_db_port);
            } else if (strcmp(key, "socket") == 0) {
                strncpy(g_db_socket, value, sizeof(g_db_socket) - 1);
                g_db_socket[sizeof(g_db_socket) - 1] = '\0';
                syslog(LOG_INFO, "Configured DB socket: %s", g_db_socket);
            } else {
                syslog(LOG_WARNING, "Unknown config key in %s: %s", CONFIG_FILE, key);
            }
        }
    }

    fclose(fp);
    return 0;
}

static int read_db_pass() {
    FILE *fp = fopen(PASSWD_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open password file %s: %s", PASSWD_FILE, strerror(errno));
        return -1;
    }
    if (fgets(g_db_password, sizeof(g_db_password), fp) == NULL) {
        syslog(LOG_ERR, "Failed to read password from file %s", PASSWD_FILE);
        fclose(fp);
        return -1;
    }
    g_db_password[strcspn(g_db_password, "\n")] = 0; // remove trailing newline
    fclose(fp);
    return 0;
}

static int read_user_limits() {
    FILE *fp = fopen(USER_LIMITS_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open user limits file %s: %s", USER_LIMITS_FILE, strerror(errno));
        return -1;
    }

    pthread_mutex_lock(&limits_mutex);
    limit_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp) && limit_count < MAX_USERS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63[^,],%lld,%lld", limits[limit_count].user,
                   &limits[limit_count].soft_limit, &limits[limit_count].hard_limit) == 3) {
            limit_count++;
        }
    }
    pthread_mutex_unlock(&limits_mutex);

    fclose(fp);
    return 0;
}

static long long check_user_storage(const char *user) {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        syslog(LOG_ERR, "mysql_init() failed in check_user_storage");
        return -1;
    }

    if (!mysql_real_connect(conn, g_db_hostname, g_db_user, g_db_password,
                            NULL, g_db_port,
                            (strlen(g_db_socket) > 0 ? g_db_socket : NULL), 0)) {
        syslog(LOG_ERR, "Failed to connect to database: %s", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    char query[256];
    char escaped_user[64 * 2 + 1];
    mysql_real_escape_string(conn, escaped_user, user, strlen(user));
    snprintf(query, sizeof(query),
             "SELECT SUM(data_length + index_length) "
             "FROM information_schema.tables WHERE table_schema = '%s'",
             escaped_user);

    if (mysql_query(conn, query)) {
        syslog(LOG_ERR, "Query failed: %s", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    if (res == NULL) {
        syslog(LOG_ERR, "mysql_store_result() failed: %s", mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    MYSQL_ROW row = mysql_fetch_row(res);
    long long usage = -1;
    if (row && row[0]) {
        usage = atoll(row[0]);
    }

    mysql_free_result(res);
    mysql_close(conn);
    return usage;
}

static void *check_user_usage_worker(void *arg) {
    char *user = (char *)arg;
    syslog(LOG_INFO, "Checking user usage for: %s", user);

    pthread_mutex_lock(&limits_mutex);
    bool found_limit = false;
    long long soft_limit = 0;
    long long hard_limit = 0;
    for (int i = 0; i < limit_count; i++) {
        if (strcmp(limits[i].user, user) == 0) {
            soft_limit = limits[i].soft_limit;
            hard_limit = limits[i].hard_limit;
            found_limit = true;
            break;
        }
    }
    pthread_mutex_unlock(&limits_mutex);

    if (!found_limit) {
        syslog(LOG_WARNING, "No limit found for user: %s. Exiting worker.", user);
        free(user);
        return NULL;
    }

    long long current_usage = check_user_storage(user);
    if (current_usage == -1) {
        syslog(LOG_ERR, "Failed to get user usage for %s. Exiting worker.", user);
        free(user);
        return NULL;
    }

    if (current_usage > hard_limit) {
        syslog(LOG_ALERT, "User %s exceeded hard limit. Locking account.", user);
        lock_user_account(user);
    } else if (current_usage > soft_limit) {
        syslog(LOG_NOTICE, "User %s exceeded soft limit. Usage: %lld bytes.", user, current_usage);
    }

    free(user);
    return NULL;
}

static void lock_user_account(const char *user) {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        syslog(LOG_ERR, "mysql_init() failed in lock_user_account");
        return;
    }

    if (!mysql_real_connect(conn, g_db_hostname, g_db_user, g_db_password,
                            NULL, g_db_port,
                            (strlen(g_db_socket) > 0 ? g_db_socket : NULL), 0)) {
        syslog(LOG_ERR, "Failed to connect to lock account for %s: %s", user, mysql_error(conn));
        mysql_close(conn);
        return;
    }

    char query[256];
    char escaped_user[64 * 2 + 1];
    mysql_real_escape_string(conn, escaped_user, user, strlen(user));
    snprintf(query, sizeof(query), "ALTER USER '%s'@'%%' ACCOUNT LOCK;", escaped_user);

    if (mysql_real_query(conn, query, strlen(query))) {
        syslog(LOG_ERR, "Failed to lock account for %s: %s", user, mysql_error(conn));
    } else {
        syslog(LOG_ALERT, "Successfully locked account for user %s due to storage overuse.", user);
    }

    mysql_close(conn);
}

static int audit_notify(MYSQL_AUDIT_INFO *audit_info, unsigned int event_class, const void *event) {
    if (event_class == MYSQL_AUDIT_GENERAL_CLASS && audit_info->general_info->event == AUDIT_EVENT_QUERY) {
        const char *query = audit_info->general_info->query;
        if (query && (strncasecmp(query, "INSERT", 6) == 0 ||
                      strncasecmp(query, "UPDATE", 6) == 0 ||
                      strncasecmp(query, "LOAD", 4) == 0)) {
            const char *user = audit_info->general_info->user;
            if (user) {
                char *user_copy = strdup(user);
                if (user_copy) {
                    pthread_t new_thread;
                    pthread_create(&new_thread, NULL, check_user_usage_worker, user_copy);
                    pthread_detach(new_thread);
                }
            }
        }
    } else if (event_class == MYSQL_AUDIT_DDL_CLASS) {
        const struct mysql_event_ddl *ev = (const struct mysql_event_ddl *)event;
        const char *user = ev->user;
        const char *cmd  = ev->ddl_query;
        if (!user || !cmd) return 0;
        char *user_copy = strdup(user);
        if (user_copy) {
            pthread_t new_thread;
            pthread_create(&new_thread, NULL, check_user_usage_worker, user_copy);
            pthread_detach(new_thread);
        }
    }
    return 0;
}

// Plugin interface
static struct st_mysql_audit audit_interface = {
    MYSQL_AUDIT_INTERFACE_VERSION,
    NULL,
    audit_notify,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// Plugin init function
static int plugin_init(void) {
    if (read_config() != 0) {
        syslog(LOG_WARNING, "Using default DB connection settings (host=%s, port=%u)", g_db_hostname, g_db_port);
    }
    if (read_db_pass() != 0 || read_user_limits() != 0) {
        syslog(LOG_ERR, "Failed to load initial configuration. Plugin will not function properly.");
        return 1;
    }
    syslog(LOG_INFO, "MySQL Monitor Audit Plugin initialized.");
    return 0;
}

// Plugin deinit function
static int plugin_deinit(void) {
    syslog(LOG_INFO, "MySQL Monitor Audit Plugin de-initialized.");
    return 0;
}

// Plugin descriptor
struct st_mysql_daemon plugin_descriptor = {
    MYSQL_DAEMON_INTERFACE_VERSION,
    plugin_init,
    plugin_deinit,
    "mysql_monitor_audit",
    "J. Doe",
    "MySQL/MariaDB Audit Plugin to lock accounts on storage overuse",
    { 0, 2, 0 }
};
