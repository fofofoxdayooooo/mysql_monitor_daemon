/**
 * @file mysql_monitor_daemon.c
 * @brief MySQL/MariaDB monitoring daemon for Linux/FreeBSD
 *
 * This version incorporates advanced features and architectural improvements for
 * high-reliability, robust monitoring and control.
 *
 * - Monitors per-user storage usage using information_schema or other methods
 * - Enforces soft/hard storage limits (locks account if exceeded)
 * - Configuration reload via SIGHUP
 * - Thread pool + task queue architecture
 * - LRU cache for frequently checked users
 * - Prometheus metrics exporter
 * - MySQL / MariaDB version-aware account locking
 *
 * New in this version:
 * - Externalized password file path via a central configuration file.
 * - Robust account locking logic using `ALTER USER ... ACCOUNT LOCK` and
 * a direct fallback to updating `mysql.user` table for older MariaDB versions.
 * - Graceful shutdown and cleanup of all threads and tasks.
 * - Configurable query method (`information_schema`, `performance_schema`, `innodb_stats`)
 * for storage usage checks to optimize for different MySQL/MariaDB versions and workloads.
 * - **New:** Detailed query sub-methods can now be configured in daemon.conf for specific tables
 * like `table_io_waits_summary_by_index_usage` or `sys.schema_table_statistics`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifdef __FreeBSD__
#include <libutil.h>
#endif

#include <mysql/mysql.h>

// ---------------------------------------------------------
// Config paths
// ---------------------------------------------------------
#define DAEMON_CONFIG_FILE "/etc/mysql_monitor/daemon.conf"
#define DB_CONFIG_FILE     "/etc/mysql_monitor/db_list"
#define USER_LIMITS_FILE "/etc/mysql_monitor/user_limits"
#define METRICS_FILE       "/var/run/mysql_monitor/metrics.prom"

// Constants
#define MAX_DBS 64
#define MAX_THREADS 8
#define MAX_DB_NAME_LEN 64
#define MAX_USER_NAME_LEN 64
#define MAX_PASS_LEN 128
#define MAX_HOSTNAME_LEN 256
#define MAX_QUERY_LEN 1024
#define LRU_CACHE_SIZE 1024

// Query methods
#define QUERY_METHOD_INFO_SCHEMA "information_schema"
#define QUERY_METHOD_PERF_SCHEMA "performance_schema"
#define QUERY_METHOD_INNODB_STATS "innodb_stats"

// Query sub-methods for performance_schema
#define QUERY_SUB_METHOD_IO_WAITS "table_io_waits"
#define QUERY_SUB_METHOD_INDEX_USAGE "table_io_waits_summary_by_index_usage"
#define QUERY_SUB_METHOD_SYS_STATS "sys.schema_table_statistics"

// ---------------------------------------------------------
// Data structures
// ---------------------------------------------------------
typedef struct {
    char hostname[MAX_HOSTNAME_LEN];
    int  port;
    char user[MAX_USER_NAME_LEN];
    char db_name[MAX_DB_NAME_LEN];
    int  monitor_interval; // seconds
    time_t last_check;
} DBConnectionInfo;

typedef struct {
    char user[MAX_USER_NAME_LEN];
    long long soft_limit;
    long long hard_limit;
} UserLimit;

typedef struct Task {
    DBConnectionInfo db_info;
    char user_to_check[MAX_USER_NAME_LEN];
    struct Task *next;
} Task;

typedef struct {
    char user[MAX_USER_NAME_LEN];
    long long usage;
    struct LRUNode *prev;
    struct LRUNode *next;
} LRUNode;

// ---------------------------------------------------------
// Globals
// ---------------------------------------------------------
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t reload_config_flag = 0;

static DBConnectionInfo db_list[MAX_DBS];
static int db_count = 0;

static UserLimit *user_limits = NULL;
static size_t user_limit_count = 0;
static size_t user_limit_capacity = 0;

static char global_passwd[MAX_PASS_LEN] = "";
static char passwd_file_path[512] = "";
static char query_method[64] = QUERY_METHOD_INFO_SCHEMA;
static char query_sub_method[128] = "";

static Task *task_queue = NULL;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

static pthread_rwlock_t config_rwlock = PTHREAD_RWLOCK_INITIALIZER;

// LRU cache
static LRUNode *lru_head = NULL;
static LRUNode *lru_tail = NULL;
static int lru_size = 0;
static pthread_mutex_t lru_mutex = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------------------------------------
// Function prototypes
// ---------------------------------------------------------
static void daemonize();
static void signal_handler(int sig);
static int read_daemon_config();
static int read_db_config();
static int read_user_limits();
static int read_passwd_config();
static void reload_all_configs();
static void cleanup_user_limits();
static void cleanup_lru();

static void add_task(Task *task);
static void *worker_function(void *arg);
static long long check_user_storage(const DBConnectionInfo *db_info, const char *user);
static void lock_user_account(const DBConnectionInfo *db_info, const char *user);
static int is_mariadb_version_less_than(const char *version_str, int major_compare, int minor_compare);

static void lru_add_or_update(const char *user, long long usage);

static void write_prometheus_metrics();

// ---------------------------------------------------------
// Daemonize
// ---------------------------------------------------------
static void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    if (setsid() < 0) exit(EXIT_FAILURE);
    if ((chdir("/")) < 0) exit(EXIT_FAILURE);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

// ---------------------------------------------------------
// Signal handler
// ---------------------------------------------------------
static void signal_handler(int sig) {
    if (sig == SIGHUP) {
        reload_config_flag = 1;
        syslog(LOG_INFO, "SIGHUP received, scheduling config reload.");
    } else if (sig == SIGTERM || sig == SIGINT) {
        keep_running = 0;
        pthread_cond_broadcast(&queue_cond);
        syslog(LOG_INFO, "Termination signal received.");
    }
}

// ---------------------------------------------------------
// Config loaders
// ---------------------------------------------------------
static int read_daemon_config() {
    FILE *fp = fopen(DAEMON_CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open daemon config %s: %s. Using defaults.",
               DAEMON_CONFIG_FILE, strerror(errno));
        snprintf(passwd_file_path, sizeof(passwd_file_path), "/root/etc/mysql_monitor/passwd");
        return 0; // Don't fail completely
    }
    char line[512];
    int found_passwd_path = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char key[128], value[256];
        if (sscanf(line, "%127[^=]=%255[^\n]", key, value) == 2) {
            if (strcmp(key, "passwd_file") == 0) {
                strncpy(passwd_file_path, value, sizeof(passwd_file_path) - 1);
                passwd_file_path[sizeof(passwd_file_path) - 1] = '\0';
                found_passwd_path = 1;
            } else if (strcmp(key, "query_method") == 0) {
                if (strcmp(value, QUERY_METHOD_INFO_SCHEMA) == 0 ||
                    strcmp(value, QUERY_METHOD_PERF_SCHEMA) == 0 ||
                    strcmp(value, QUERY_METHOD_INNODB_STATS) == 0) {
                    strncpy(query_method, value, sizeof(query_method) - 1);
                    query_method[sizeof(query_method) - 1] = '\0';
                    syslog(LOG_INFO, "Query method set to: %s", query_method);
                } else {
                    syslog(LOG_WARNING, "Invalid query_method '%s'. Using default 'information_schema'.", value);
                }
            } else if (strcmp(key, "query_sub_method") == 0) {
                 if (strcmp(value, QUERY_SUB_METHOD_IO_WAITS) == 0 ||
                    strcmp(value, QUERY_SUB_METHOD_INDEX_USAGE) == 0 ||
                    strcmp(value, QUERY_SUB_METHOD_SYS_STATS) == 0) {
                    strncpy(query_sub_method, value, sizeof(query_sub_method) - 1);
                    query_sub_method[sizeof(query_sub_method) - 1] = '\0';
                    syslog(LOG_INFO, "Query sub-method set to: %s", query_sub_method);
                } else {
                    syslog(LOG_WARNING, "Invalid query_sub_method '%s'. Defaulting.", value);
                }
            }
        }
    }
    fclose(fp);
    if (!found_passwd_path) {
        snprintf(passwd_file_path, sizeof(passwd_file_path), "/root/etc/mysql_monitor/passwd");
        syslog(LOG_WARNING, "passwd_file not found in %s. Using default path.", DAEMON_CONFIG_FILE);
    }
    syslog(LOG_INFO, "Loaded daemon config. Password file path: %s", passwd_file_path);
    return 0;
}

static int read_passwd_config() {
    if (strlen(passwd_file_path) == 0) {
        syslog(LOG_ERR, "Password file path is not configured.");
        return -1;
    }
    FILE *fp = fopen(passwd_file_path, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open password file %s: %s",
               passwd_file_path, strerror(errno));
        return -1;
    }
    if (!fgets(global_passwd, sizeof(global_passwd), fp)) {
        fclose(fp);
        syslog(LOG_ERR, "Failed to read password from %s", passwd_file_path);
        return -1;
    }
    global_passwd[strcspn(global_passwd, "\n")] = 0;
    fclose(fp);
    return 0;
}

static int read_db_config() {
    FILE *fp = fopen(DB_CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open db config %s: %s",
               DB_CONFIG_FILE, strerror(errno));
        return -1;
    }
    db_count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && db_count < MAX_DBS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        DBConnectionInfo *db = &db_list[db_count];
        if (sscanf(line, "%255[^,],%d,%63[^,],%63[^,],%d",
                   db->hostname, &db->port,
                   db->user, db->db_name, &db->monitor_interval) == 5) {
            db->last_check = 0;
            db_count++;
        }
    }
    fclose(fp);
    syslog(LOG_INFO, "Loaded %d databases from config.", db_count);
    return 0;
}

static int read_user_limits() {
    FILE *fp = fopen(USER_LIMITS_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open user limits %s: %s",
               USER_LIMITS_FILE, strerror(errno));
        return -1;
    }
    cleanup_user_limits();

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        UserLimit tmp;
        if (sscanf(line, "%63[^,],%lld,%lld",
                   tmp.user, &tmp.soft_limit, &tmp.hard_limit) == 3) {
            if (user_limit_count >= user_limit_capacity) {
                size_t new_cap = (user_limit_capacity == 0) ? 128 : user_limit_capacity * 2;
                UserLimit *new_limits = realloc(user_limits, new_cap * sizeof(UserLimit));
                if (!new_limits) {
                    syslog(LOG_ERR, "Failed realloc user_limits. Aborting load.");
                    break;
                }
                user_limits = new_limits;
                user_limit_capacity = new_cap;
            }
            user_limits[user_limit_count++] = tmp;
        }
    }
    fclose(fp);
    syslog(LOG_INFO, "Loaded %zu user limits.", user_limit_count);
    return 0;
}

static void reload_all_configs() {
    pthread_rwlock_wrlock(&config_rwlock);
    read_daemon_config();
    read_db_config();
    read_user_limits();
    read_passwd_config();
    reload_config_flag = 0;
    pthread_rwlock_unlock(&config_rwlock);
    syslog(LOG_INFO, "Configuration reload complete.");
}

// ---------------------------------------------------------
// Cleanup
// ---------------------------------------------------------
static void cleanup_user_limits() {
    free(user_limits);
    user_limits = NULL;
    user_limit_count = 0;
    user_limit_capacity = 0;
}

static void cleanup_lru() {
    pthread_mutex_lock(&lru_mutex);
    LRUNode *cur = lru_head;
    while (cur) {
        LRUNode *tmp = cur->next;
        free(cur);
        cur = tmp;
    }
    lru_head = lru_tail = NULL;
    lru_size = 0;
    pthread_mutex_unlock(&lru_mutex);
}

// ---------------------------------------------------------
// Task queue
// ---------------------------------------------------------
static void add_task(Task *task) {
    pthread_mutex_lock(&queue_mutex);
    task->next = NULL;
    if (!task_queue) {
        task_queue = task;
    } else {
        Task *cur = task_queue;
        while (cur->next) cur = cur->next;
        cur->next = task;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

// ---------------------------------------------------------
// Worker function
// ---------------------------------------------------------
static void *worker_function(void *arg) {
    (void)arg;
    while (keep_running) {
        pthread_mutex_lock(&queue_mutex);
        while (!task_queue && keep_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        if (!keep_running) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        Task *task = task_queue;
        if (task) task_queue = task->next;
        pthread_mutex_unlock(&queue_mutex);

        if (task) {
            long long usage = check_user_storage(&task->db_info, task->user_to_check);
            if (usage >= 0) {
                pthread_rwlock_rdlock(&config_rwlock);
                for (size_t i = 0; i < user_limit_count; i++) {
                    if (strcmp(user_limits[i].user, task->user_to_check) == 0) {
                        if (usage > user_limits[i].hard_limit) {
                            syslog(LOG_ALERT, "User '%s' exceeded hard limit on '%s'. Locking account.",
                                   task->user_to_check, task->db_info.db_name);
                            lock_user_account(&task->db_info, task->user_to_check);
                        } else if (usage > user_limits[i].soft_limit) {
                            syslog(LOG_NOTICE, "User '%s' exceeded soft limit on '%s': %lld bytes",
                                   task->user_to_check, task->db_info.db_name, usage);
                        }
                        break;
                    }
                }
                pthread_rwlock_unlock(&config_rwlock);
                lru_add_or_update(task->user_to_check, usage);
            }
            free(task);
        }
    }
    return NULL;
}

// ---------------------------------------------------------
// DB check and lock
// ---------------------------------------------------------
/**
 * @brief Checks a user's total storage usage using a configurable query method.
 */
static long long check_user_storage(const DBConnectionInfo *db_info, const char *user) {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        syslog(LOG_ERR, "Failed to initialize MySQL connection handle.");
        return -1;
    }
    // Connect to the specific database if needed, or to NULL database for global queries
    pthread_rwlock_rdlock(&config_rwlock);
    const char *current_query_method = query_method;
    const char *current_query_sub_method = query_sub_method;
    pthread_rwlock_unlock(&config_rwlock);

    if (!mysql_real_connect(conn, db_info->hostname, db_info->user, global_passwd,
                            strcmp(current_query_method, QUERY_METHOD_INNODB_STATS) == 0 ||
                            strcmp(current_query_sub_method, QUERY_SUB_METHOD_SYS_STATS) == 0 ? "mysql" : db_info->db_name,
                            db_info->port, NULL, 0)) {
        syslog(LOG_ERR, "DB connect failed to %s:%d, db: %s, for user: %s: %s",
               db_info->hostname, db_info->port,
               db_info->db_name, user, mysql_error(conn));
        mysql_close(conn);
        return -1;
    }

    char query[MAX_QUERY_LEN];
    long long usage = -1;

    if (strcmp(current_query_method, QUERY_METHOD_PERF_SCHEMA) == 0) {
        if (strcmp(current_query_sub_method, QUERY_SUB_METHOD_INDEX_USAGE) == 0) {
             snprintf(query, sizeof(query),
                     "SELECT IFNULL(SUM(rows_fetched), 0) FROM performance_schema.table_io_waits_summary_by_index_usage WHERE object_schema = '%s'", user);
        } else if (strcmp(current_query_sub_method, QUERY_SUB_METHOD_SYS_STATS) == 0) {
            snprintf(query, sizeof(query),
                     "SELECT IFNULL(SUM(data_length + index_length), 0) FROM sys.schema_table_statistics WHERE table_schema = '%s'", user);
        } else {
            // Default sub-method for performance_schema
            snprintf(query, sizeof(query),
                     "SELECT IFNULL(SUM(count_read), 0) + IFNULL(SUM(count_write), 0) FROM performance_schema.table_io_waits_summary_by_table "
                     "WHERE object_schema = '%s'", user);
        }
    } else if (strcmp(current_query_method, QUERY_METHOD_INNODB_STATS) == 0) {
        snprintf(query, sizeof(query),
                 "SELECT IFNULL(SUM(data_length + index_length), 0) "
                 "FROM mysql.innodb_table_stats WHERE database_name = '%s'", user);
    } else {
        // Default to information_schema for broad compatibility
        snprintf(query, sizeof(query),
                 "SELECT IFNULL(SUM(data_length+index_length),0) "
                 "FROM information_schema.tables WHERE table_schema='%s'", user);
    }

    if (mysql_query(conn, query)) {
        syslog(LOG_ERR, "Query failed for user %s on db %s (method: %s, sub-method: %s): %s",
               user, db_info->db_name, current_query_method, current_query_sub_method, mysql_error(conn));

        // Fallback logic
        snprintf(query, sizeof(query),
                 "SELECT IFNULL(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='%s'", user);
        if (mysql_query(conn, query)) {
            syslog(LOG_ERR, "Fallback query also failed for user %s on db %s: %s", user, db_info->db_name, mysql_error(conn));
            mysql_close(conn);
            return -1;
        } else {
            syslog(LOG_WARNING, "Falling back to information_schema query due to failure.");
        }
    }
    
    MYSQL_RES *res = mysql_store_result(conn);
    if (res) {
        MYSQL_ROW row = mysql_fetch_row(res);
        usage = (row && row[0]) ? atoll(row[0]) : 0;
        mysql_free_result(res);
    }
    
    mysql_close(conn);
    return usage;
}

static int is_mariadb_version_less_than(const char *version_str, int major_compare, int minor_compare) {
    if (!version_str || !strstr(version_str, "MariaDB")) {
        return 0; // Not MariaDB
    }
    int major_version = 0, minor_version = 0;
    if (sscanf(version_str, "%d.%d", &major_version, &minor_version) == 2) {
        if (major_version < major_compare) {
            return 1;
        }
        if (major_version == major_compare && minor_version < minor_compare) {
            return 1;
        }
    }
    return 0;
}

static void lock_user_account(const DBConnectionInfo *db_info, const char *user) {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) return;
    if (!mysql_real_connect(conn, db_info->hostname, db_info->user, global_passwd,
                            NULL, db_info->port, NULL, 0)) {
        mysql_close(conn);
        return;
    }
    const char *server_version = mysql_get_server_info(conn);
    char query[MAX_QUERY_LEN];

    if (is_mariadb_version_less_than(server_version, 10, 4)) {
        syslog(LOG_WARNING, "Using legacy REVOKE for user '%s' on MariaDB < 10.4.", user);
        snprintf(query, sizeof(query),
                 "REVOKE ALL PRIVILEGES, GRANT OPTION FROM '%s'@'%%'", user);
    } else {
        snprintf(query, sizeof(query),
                 "ALTER USER '%s'@'%%' ACCOUNT LOCK", user);
    }
    if (mysql_query(conn, query)) {
        if (is_mariadb_version_less_than(server_version, 10, 4)) {
            syslog(LOG_ERR, "REVOKE failed for %s. Trying direct user table update.", user);
            snprintf(query, sizeof(query),
                     "UPDATE mysql.user SET account_locked = 'Y' WHERE user = '%s'", user);
            if (mysql_query(conn, query) || mysql_query(conn, "FLUSH PRIVILEGES")) {
                syslog(LOG_ERR, "Direct user table update failed for %s: %s", user, mysql_error(conn));
            } else {
                syslog(LOG_INFO, "Account locked via direct table update for %s", user);
            }
        } else {
            syslog(LOG_ERR, "Account lock failed for %s on %s:%d: %s", user, db_info->hostname, db_info->port, mysql_error(conn));
        }
    } else {
        syslog(LOG_INFO, "Account locked for %s on %s:%d", user, db_info->hostname, db_info->port);
    }
    mysql_close(conn);
}

// ---------------------------------------------------------
// LRU cache
// ---------------------------------------------------------
static void lru_add_or_update(const char *user, long long usage) {
    pthread_mutex_lock(&lru_mutex);
    LRUNode *cur = lru_head;
    while (cur) {
        if (strcmp(cur->user, user) == 0) {
            cur->usage = usage;
            if (cur != lru_head) {
                if (cur->prev) cur->prev->next = cur->next;
                if (cur->next) cur->next->prev = cur->prev;
                if (cur == lru_tail) lru_tail = cur->prev;
                cur->prev = NULL;
                cur->next = lru_head;
                if (lru_head) lru_head->prev = cur;
                lru_head = cur;
            }
            pthread_mutex_unlock(&lru_mutex);
            return;
        }
        cur = cur->next;
    }
    LRUNode *node = malloc(sizeof(LRUNode));
    if (!node) {
        syslog(LOG_ERR, "Failed to allocate memory for LRU node.");
        pthread_mutex_unlock(&lru_mutex);
        return;
    }
    strncpy(node->user, user, MAX_USER_NAME_LEN-1);
    node->user[MAX_USER_NAME_LEN-1] = '\0';
    node->usage = usage;
    node->prev = NULL;
    node->next = lru_head;
    if (lru_head) lru_head->prev = node;
    lru_head = node;
    if (!lru_tail) lru_tail = node;
    if (++lru_size > LRU_CACHE_SIZE) {
        LRUNode *old = lru_tail;
        if (old->prev) old->prev->next = NULL;
        lru_tail = old->prev;
        free(old);
        lru_size--;
    }
    pthread_mutex_unlock(&lru_mutex);
}

// ---------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------
static void write_prometheus_metrics() {
    FILE *fp = fopen(METRICS_FILE, "w");
    if (!fp) return;
    fprintf(fp, "# HELP mysql_monitor_storage_usage_bytes Total usage per user\n");
    fprintf(fp, "# TYPE mysql_monitor_storage_usage_bytes gauge\n");
    pthread_mutex_lock(&lru_mutex);
    LRUNode *cur = lru_head;
    while (cur) {
        fprintf(fp, "mysql_monitor_storage_usage_bytes{user=\"%s\"} %lld\n",
                cur->user, cur->usage);
        cur = cur->next;
    }
    pthread_mutex_unlock(&lru_mutex);
    fclose(fp);
}

// ---------------------------------------------------------
// Main
// ---------------------------------------------------------
int main() {
    daemonize();
    openlog("mysql_monitor_daemon", LOG_PID, LOG_DAEMON);
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    if (read_daemon_config() != 0 || read_db_config() != 0 || read_user_limits() != 0 || read_passwd_config() != 0) {
        syslog(LOG_ERR, "Initial config load failed. Exiting.");
        return EXIT_FAILURE;
    }

    pthread_t workers[MAX_THREADS];
    for (int i=0;i<MAX_THREADS;i++) {
        pthread_create(&workers[i], NULL, worker_function, NULL);
    }

    syslog(LOG_INFO, "Daemon started.");
    while (keep_running) {
        if (reload_config_flag) {
            reload_all_configs();
        }

        time_t now = time(NULL);
        pthread_rwlock_rdlock(&config_rwlock);
        for (int i=0;i<db_count;i++) {
            if (now >= db_list[i].last_check + db_list[i].monitor_interval) {
                for (size_t j=0;j<user_limit_count;j++) {
                    Task *task = malloc(sizeof(Task));
                    if (!task) {
                        syslog(LOG_ERR, "Failed to allocate memory for a new task.");
                        continue;
                    }
                    task->db_info = db_list[i];
                    strncpy(task->user_to_check, user_limits[j].user, MAX_USER_NAME_LEN-1);
                    task->user_to_check[MAX_USER_NAME_LEN-1]='\0';
                    add_task(task);
                }
                db_list[i].last_check = now;
            }
        }
        pthread_rwlock_unlock(&config_rwlock);
        write_prometheus_metrics();

        struct timespec ts;
        now = time(NULL);
        ts.tv_sec = now + 5;
        ts.tv_nsec = 0;
        pthread_mutex_lock(&queue_mutex);
        pthread_cond_timedwait(&queue_cond, &queue_mutex, &ts);
        pthread_mutex_unlock(&queue_mutex);
    }

    syslog(LOG_INFO, "Shutting down daemon...");
    pthread_mutex_lock(&queue_mutex);
    keep_running = 0;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    for (int i=0;i<MAX_THREADS;i++) {
        pthread_join(workers[i], NULL);
    }

    while (task_queue) {
        Task *tmp = task_queue;
        task_queue = task_queue->next;
        free(tmp);
    }

    cleanup_user_limits();
    cleanup_lru();
    closelog();
    return 0;
}
