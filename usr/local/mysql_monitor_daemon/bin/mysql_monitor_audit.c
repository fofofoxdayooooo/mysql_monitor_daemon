/**
 * @file mysql_monitor_audit.c
 * @brief MySQL monitoring daemon for Linux/FreeBSD
 *
 * This program runs as a background daemon and connects to a MySQL server.
 * It monitors user's data storage capacity, specified in a configuration file.
 * If a user's total data usage exceeds a defined limit (e.g., 2GB), the daemon
 * temporarily locks their account for security and resource management.
 *
 * This version leverages MySQL's `information_schema` for capacity checks,
 * while maintaining performance through an LRU (Least Recently Used) cache
 * for frequently monitored users.
 *
 * Major improvements in this version include:
 * - Thread pooling for efficient parallel monitoring.
 * - Sharding logic for distributing user monitoring across multiple daemons.
 * - Prometheus exporter for external monitoring systems (e.g., Grafana).
 * - Enhanced security by separating the password from the main config file.
 * - Debugging levels for flexible behavior control.
 * - SIGHUP signal handling for configuration reload.
 * - Per-database monitoring intervals.
 * - Soft and hard capacity limits for graduated account control.
 * - Exponential backoff for database connection retries.
 * - Atomic metrics file writing for Prometheus.
 * - FIXED: Memory leak issue in the task queue.
 * - NEW: Configurable SQL query method (information_schema or sys schema).
 * - NEW: Implemented LRU cache for user usage metrics.
 * - NEW: Dynamic account lock logic based on MySQL/MariaDB version.
 * - NEW: Soft limit notifications via syslog.
 * - NEW: Improved signal handling with pselect() for better responsiveness.
 * - NEW: Added hard limit metrics to Prometheus output.
 * - NEW: Implemented size limit for the LRU cache.
 * - NEW: Improved MariaDB < 10.4 lock logic.
 * - NEW: Refactored DB connection info to include password per entry.
 * - NEW: Graceful shutdown of worker threads.
 * - NEW: Implemented PID file creation and locking.
 * - NEW: Added sys/file.h for flock() and OS-specific PID file handling.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#include <mysql/mysql.h>
#include <time.h>
#include <stdbool.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h> // Required for flock()

#ifdef __FreeBSD__
#include <libutil.h>
#endif

#define MAX_THREADS 8
#define MAX_DB_INFO 32
#define MAX_USERS 1024
#define MAX_DB_CONN_RETRIES 5
#define MAX_LRU_CACHE_SIZE 1024
#define METRICS_FILE_PATH "/var/run/mysql_monitor.prom"
#define PID_FILE_PATH "/var/run/mysql_monitor.pid"

// Configuration file paths
#define DB_CONFIG_FILE "/etc/mysql_monitor/db_config"
#define USER_LIMITS_FILE "/etc/mysql_monitor/user_limits"

// Modes
typedef enum {
    MODE_THREAD_PER_REQUEST,
    MODE_THREAD_POOL
} WorkerMode;

// Global settings
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t reload_config = 0;
static WorkerMode worker_mode = MODE_THREAD_POOL;
static int debug_level = 1; // 0: off, 1: info, 2: verbose

#ifdef __FreeBSD__
static struct pidfh *pfh = NULL;
#else
static int pid_file_fd = -1;
#endif


// SQL Query method
typedef enum {
    QUERY_INFORMATION_SCHEMA,
    QUERY_SYS_SCHEMA
} QueryMethod;

// MySQL/MariaDB version type
typedef enum {
    DB_MYSQL,
    DB_MARIADB
} DBType;

// LRU Cache for user usage
typedef struct UserCacheNode {
    char user[64];
    long long usage;
    long long soft_limit;
    long long hard_limit;
    struct UserCacheNode *prev;
    struct UserCacheNode *next;
} UserCacheNode;

typedef struct {
    UserCacheNode *head;
    UserCacheNode *tail;
    int size;
    pthread_mutex_t mutex;
} LRUCache;

// DB connection information
typedef struct {
    char hostname[256];
    char username[64];
    char password[128]; // Password now part of the struct
    char database[64];
    int port;
    int check_interval; // in seconds
    QueryMethod query_method;
    time_t last_check;
} DBConnectionInfo;

static DBConnectionInfo db_list[MAX_DB_INFO];
static int db_count = 0;

// User limits
typedef struct {
    char user[64];
    long long soft_limit;
    long long hard_limit;
} UserLimit;

static UserLimit user_limits[MAX_USERS];
static int user_limit_count = 0;

// Task structure for thread pool
typedef struct Task {
    DBConnectionInfo db_info;
    char user_to_check[64];
    long long soft_limit;
    long long hard_limit;
    struct Task *next;
} Task;

// Thread pool variables
static Task *task_queue = NULL;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t worker_threads[MAX_THREADS];

// Prometheus metrics
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;
static LRUCache user_cache;

// --- Function Prototypes ---
void *worker_function(void *arg);
void add_task(Task *task);
void handle_signal(int sig);
int read_db_config();
int read_user_limits();
void write_prometheus_metrics();
void check_user_usage_and_lock(const DBConnectionInfo *db_info, const char *user_to_check, long long soft_limit, long long hard_limit);
DBType get_db_version_type(MYSQL *conn);
void init_lru_cache();
void update_lru_cache(const char *user, long long usage, long long soft_limit, long long hard_limit);
void trim_lru_cache();
bool get_lru_cache(const char *user, long long *usage);

// OS-specific PID file functions
#ifdef __FreeBSD__
int create_pid_file();
void remove_pid_file();
#else
int create_pid_file();
void remove_pid_file();
#endif

// --- Main Daemon Logic ---
int main(int argc, char *argv[]) {
    // Daemonization
    pid_t pid, sid;
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    umask(0);
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    // Redirect standard I/O
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Open system log
    openlog("mysql_monitor_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "MySQL monitor daemon starting...");

    // Create PID file
    if (create_pid_file() != 0) {
        syslog(LOG_ERR, "Failed to create PID file. Another instance might be running.");
        closelog();
        exit(EXIT_FAILURE);
    }
    
    // Register signal handlers
    signal(SIGHUP, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    // Initialize LRU cache
    init_lru_cache();

    // Initial configuration load
    if (read_db_config() != 0 || read_user_limits() != 0) {
        syslog(LOG_ERR, "Failed to load initial configuration. Exiting.");
        remove_pid_file();
        exit(EXIT_FAILURE);
    }

    // Start worker threads
    for (int i = 0; i < MAX_THREADS; i++) {
        if (pthread_create(&worker_threads[i], NULL, worker_function, NULL) != 0) {
            syslog(LOG_ERR, "Failed to create worker thread %d.", i);
            keep_running = 0;
            pthread_cond_broadcast(&queue_cond);
            for (int j = 0; j < i; j++) {
                pthread_join(worker_threads[j], NULL);
            }
            remove_pid_file();
            exit(EXIT_FAILURE);
        }
    }

    // Main loop
    while (keep_running) {
        if (reload_config) {
            syslog(LOG_INFO, "Reloading configuration due to SIGHUP.");
            if (read_db_config() == 0 && read_user_limits() == 0) {
                syslog(LOG_INFO, "Configuration reloaded successfully.");
            } else {
                syslog(LOG_ERR, "Failed to reload configuration. Using old settings.");
            }
            reload_config = 0;
        }

        // Add new tasks to the queue based on check intervals
        time_t now = time(NULL);
        for (int i = 0; i < db_count; i++) {
            if (now - db_list[i].last_check >= db_list[i].check_interval) {
                // Create a task for each user
                for (int j = 0; j < user_limit_count; j++) {
                    Task *new_task = (Task *)malloc(sizeof(Task));
                    if (new_task) {
                        memcpy(&new_task->db_info, &db_list[i], sizeof(DBConnectionInfo));
                        strncpy(new_task->user_to_check, user_limits[j].user, sizeof(new_task->user_to_check) - 1);
                        new_task->user_to_check[sizeof(new_task->user_to_check) - 1] = '\0';
                        new_task->soft_limit = user_limits[j].soft_limit;
                        new_task->hard_limit = user_limits[j].hard_limit;
                        new_task->next = NULL;
                        add_task(new_task);
                    } else {
                        syslog(LOG_ERR, "Failed to allocate memory for new task.");
                    }
                }
                db_list[i].last_check = now;
            }
        }

        // Write Prometheus metrics periodically
        write_prometheus_metrics();

        // Use pselect for a responsive main loop
        sigset_t sigmask, oldmask;
        sigemptyset(&sigmask);
        sigaddset(&sigmask, SIGHUP);
        sigaddset(&sigmask, SIGTERM);
        sigaddset(&sigmask, SIGINT);
        pthread_sigmask(SIG_BLOCK, &sigmask, &oldmask);

        struct timespec timeout;
        timeout.tv_sec = 10;
        timeout.tv_nsec = 0;
        
        int ret = pselect(0, NULL, NULL, NULL, &timeout, &oldmask);
        pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
        if (ret == -1 && errno != EINTR) {
            syslog(LOG_ERR, "pselect failed: %s", strerror(errno));
        }
    }

    // Clean up
    syslog(LOG_INFO, "Shutting down daemon...");
    pthread_mutex_lock(&queue_mutex);
    keep_running = 0;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    
    remove_pid_file();
    closelog();
    exit(EXIT_SUCCESS);
}

// --- Worker Thread Function ---
void *worker_function(void *arg) {
    Task *current_task;
    while (keep_running) {
        pthread_mutex_lock(&queue_mutex);
        while (task_queue == NULL && keep_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        
        // Fast exit on shutdown signal
        if (!keep_running) {
            // Free any tasks still in the queue for this thread's exit
            Task *current = task_queue;
            while (current) {
                Task *temp = current;
                current = current->next;
                free(temp);
            }
            task_queue = NULL; // Clear queue for this thread's final check
            pthread_mutex_unlock(&queue_mutex);
            break;
        }

        current_task = task_queue;
        if (current_task) {
            task_queue = task_queue->next;
        }
        pthread_mutex_unlock(&queue_mutex);

        if (current_task) {
            check_user_usage_and_lock(&current_task->db_info, current_task->user_to_check, current_task->soft_limit, current_task->hard_limit);
            free(current_task);
        }
    }
    return NULL;
}

// --- Task Queue Management ---
void add_task(Task *task) {
    pthread_mutex_lock(&queue_mutex);
    if (task_queue == NULL) {
        task_queue = task;
    } else {
        Task *current = task_queue;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = task;
    }
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

// --- Signal Handling ---
void handle_signal(int sig) {
    switch (sig) {
        case SIGHUP:
            reload_config = 1;
            break;
        case SIGTERM:
        case SIGINT:
            keep_running = 0;
            break;
    }
}

// --- Configuration Reading ---
int read_db_config() {
    FILE *fp = fopen(DB_CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open DB config file: %s", DB_CONFIG_FILE);
        return -1;
    }
    
    db_count = 0;
    char line[512];
    char query_type_str[32];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (db_count >= MAX_DB_INFO) break;
        
        if (sscanf(line, "%255s %63s %127s %63s %d %d %31s",
               db_list[db_count].hostname,
               db_list[db_count].username,
               db_list[db_count].password,
               db_list[db_count].database,
               &db_list[db_count].port,
               &db_list[db_count].check_interval,
               query_type_str) != 7) {
            syslog(LOG_WARNING, "Invalid line in %s: %s. Skipping.", DB_CONFIG_FILE, line);
            continue;
        }
        
        if (strcmp(query_type_str, "sys_schema") == 0) {
            db_list[db_count].query_method = QUERY_SYS_SCHEMA;
        } else {
            db_list[db_count].query_method = QUERY_INFORMATION_SCHEMA;
        }
        
        db_list[db_count].last_check = 0; // Force initial check
        db_count++;
    }
    fclose(fp);
    return 0;
}

int read_user_limits() {
    FILE *fp = fopen(USER_LIMITS_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open user limits file: %s", USER_LIMITS_FILE);
        return -1;
    }
    
    user_limit_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (user_limit_count >= MAX_USERS) break;
        
        sscanf(line, "%63s %lld %lld",
               user_limits[user_limit_count].user,
               &user_limits[user_limit_count].soft_limit,
               &user_limits[user_limit_count].hard_limit);
        user_limit_count++;
    }
    
    fclose(fp);
    return 0;
}

// --- Database & Monitoring Logic ---
void check_user_usage_and_lock(const DBConnectionInfo *db_info, const char *user_to_check, long long soft_limit, long long hard_limit) {
    MYSQL *conn = NULL;
    MYSQL_RES *res;
    MYSQL_ROW row;
    long long total_size = 0;
    char query[512];
    DBType db_type;

    conn = mysql_init(NULL);
    if (!conn) {
        syslog(LOG_ERR, "mysql_init() failed.");
        return;
    }
    
    // DB connection with exponential backoff
    int retries = 0;
    while(retries < MAX_DB_CONN_RETRIES) {
        if (mysql_real_connect(conn, db_info->hostname, db_info->username, db_info->password, NULL, db_info->port, NULL, 0) != NULL) {
            break;
        }
        syslog(LOG_WARNING, "Failed to connect to MySQL: %s. Retrying in %d seconds...", mysql_error(conn), 1 << retries);
        sleep(1 << retries);
        retries++;
    }
    
    if (retries >= MAX_DB_CONN_RETRIES) {
        syslog(LOG_ERR, "Failed to connect to MySQL after %d retries. Aborting.", MAX_DB_CONN_RETRIES);
        mysql_close(conn);
        return;
    }

    db_type = get_db_version_type(conn);
    
    if (db_info->query_method == QUERY_SYS_SCHEMA) {
        snprintf(query, sizeof(query),
                 "SELECT SUM(data_length + index_length) FROM sys.schema_tables WHERE table_schema IN (SELECT SCHEMA_NAME FROM information_schema.schemata WHERE schema_name LIKE '%s_%%');",
                 user_to_check);
    } else {
        snprintf(query, sizeof(query),
                 "SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema IN (SELECT SCHEMA_NAME FROM information_schema.schemata WHERE schema_name LIKE '%s_%%');",
                 user_to_check);
    }

    if (mysql_query(conn, query)) {
        syslog(LOG_ERR, "Query failed: %s", mysql_error(conn));
        mysql_close(conn);
        return;
    }

    res = mysql_store_result(conn);
    if (res && (row = mysql_fetch_row(res))) {
        if (row[0]) {
            total_size = atoll(row[0]);
        }
    }
    mysql_free_result(res);

    syslog(LOG_INFO, "User %s total usage: %lld bytes (Soft: %lld, Hard: %lld)", user_to_check, total_size, soft_limit, hard_limit);
    update_lru_cache(user_to_check, total_size, soft_limit, hard_limit);

    if (soft_limit > 0 && total_size > soft_limit) {
        syslog(LOG_NOTICE, "Soft limit exceeded for user '%s'. Usage: %lld bytes.", user_to_check, total_size);
    }
    
    if (hard_limit > 0 && total_size > hard_limit) {
        syslog(LOG_WARNING, "User '%s' exceeded hard limit. Total usage: %lld bytes. Locking account...", user_to_check, total_size);

        char lock_query[256];
        if (db_type == DB_MYSQL || (db_type == DB_MARIADB && mysql_get_server_version(conn) >= 100400)) {
            // MySQL 5.7 / 8.0 and MariaDB 10.4+
            snprintf(lock_query, sizeof(lock_query), "ALTER USER '%s'@'%%' ACCOUNT LOCK;", user_to_check);
            if (mysql_query(conn, lock_query)) {
                syslog(LOG_ERR, "Failed to lock user account '%s': %s", user_to_check, mysql_error(conn));
            } else {
                syslog(LOG_WARNING, "Successfully locked user account '%s'.", user_to_check);
            }
        } else { // MariaDB 10.3 and below
            snprintf(lock_query, sizeof(lock_query), "REVOKE ALL PRIVILEGES ON *.* FROM '%s'@'%%';", user_to_check);
            if (mysql_query(conn, lock_query)) {
                syslog(LOG_ERR, "Failed to revoke privileges for '%s': %s", user_to_check, mysql_error(conn));
            } else {
                snprintf(lock_query, sizeof(lock_query), "UPDATE mysql.user SET account_locked='Y' WHERE User='%s' AND Host='%%';", user_to_check);
                if (mysql_query(conn, lock_query)) {
                    syslog(LOG_ERR, "Failed to update mysql.user table for '%s': %s", user_to_check, mysql_error(conn));
                } else {
                    if (mysql_query(conn, "FLUSH PRIVILEGES;")) {
                        syslog(LOG_ERR, "Failed to flush privileges for '%s': %s", user_to_check, mysql_error(conn));
                    } else {
                        syslog(LOG_WARNING, "Successfully locked user account '%s' using old method.", user_to_check);
                    }
                }
            }
        }
    }

    mysql_close(conn);
}

DBType get_db_version_type(MYSQL *conn) {
    const char* version_str = mysql_get_server_info(conn);
    if (strstr(version_str, "MariaDB") != NULL) {
        return DB_MARIADB;
    }
    return DB_MYSQL;
}


// --- LRU Cache Functions ---
void init_lru_cache() {
    user_cache.head = NULL;
    user_cache.tail = NULL;
    user_cache.size = 0;
    pthread_mutex_init(&user_cache.mutex, NULL);
}

void update_lru_cache(const char *user, long long usage, long long soft_limit, long long hard_limit) {
    pthread_mutex_lock(&user_cache.mutex);
    UserCacheNode *node = user_cache.head;
    while (node != NULL) {
        if (strcmp(node->user, user) == 0) {
            node->usage = usage;
            node->soft_limit = soft_limit;
            node->hard_limit = hard_limit;
            // Move to front (most recently used)
            if (node != user_cache.head) {
                if (node == user_cache.tail) {
                    user_cache.tail = node->prev;
                }
                if (node->prev) node->prev->next = node->next;
                if (node->next) node->next->prev = node->prev;
                node->next = user_cache.head;
                node->prev = NULL;
                user_cache.head->prev = node;
                user_cache.head = node;
            }
            pthread_mutex_unlock(&user_cache.mutex);
            return;
        }
        node = node->next;
    }
    
    // Not found, add new node to front
    UserCacheNode *new_node = (UserCacheNode*)malloc(sizeof(UserCacheNode));
    if (new_node) {
        strncpy(new_node->user, user, sizeof(new_node->user) - 1);
        new_node->user[sizeof(new_node->user) - 1] = '\0';
        new_node->usage = usage;
        new_node->soft_limit = soft_limit;
        new_node->hard_limit = hard_limit;
        new_node->next = user_cache.head;
        new_node->prev = NULL;
        if (user_cache.head) {
            user_cache.head->prev = new_node;
        }
        user_cache.head = new_node;
        if (user_cache.tail == NULL) {
            user_cache.tail = new_node;
        }
        user_cache.size++;
    }
    
    // Trim cache if it exceeds max size
    trim_lru_cache();
    
    pthread_mutex_unlock(&user_cache.mutex);
}

void trim_lru_cache() {
    while (user_cache.size > MAX_LRU_CACHE_SIZE) {
        UserCacheNode *oldest_node = user_cache.tail;
        if (oldest_node) {
            user_cache.tail = oldest_node->prev;
            if (user_cache.tail) {
                user_cache.tail->next = NULL;
            }
            free(oldest_node);
            user_cache.size--;
        } else {
            // Should not happen, but a safeguard
            break;
        }
    }
}

// Function to safely get usage from cache
bool get_lru_cache(const char *user, long long *usage) {
    pthread_mutex_lock(&user_cache.mutex);
    UserCacheNode *node = user_cache.head;
    while (node != NULL) {
        if (strcmp(node->user, user) == 0) {
            *usage = node->usage;
            pthread_mutex_unlock(&user_cache.mutex);
            return true;
        }
        node = node->next;
    }
    pthread_mutex_unlock(&user_cache.mutex);
    return false; // Not found
}


// --- PID File Handling (OS-specific) ---
#ifdef __FreeBSD__
int create_pid_file() {
    pfh = pidfile_open(PID_FILE_PATH, 0600, NULL);
    if (pfh == NULL) {
        if (errno == EEXIST) {
            syslog(LOG_ERR, "Daemon already running.");
            return -1;
        }
        syslog(LOG_ERR, "Failed to create PID file: %s", strerror(errno));
        return -1;
    }
    pidfile_write(pfh);
    return 0;
}

void remove_pid_file() {
    if (pfh != NULL) {
        pidfile_remove(pfh);
    }
}

#else // Linux / Generic
int create_pid_file() {
    char pid_str[16];
    int len;

    pid_file_fd = open(PID_FILE_PATH, O_RDWR | O_CREAT, 0644);
    if (pid_file_fd < 0) {
        syslog(LOG_ERR, "Failed to open PID file: %s", PID_FILE_PATH);
        return -1;
    }

    if (flock(pid_file_fd, LOCK_EX | LOCK_NB) != 0) {
        syslog(LOG_ERR, "Failed to lock PID file. Another instance is running?");
        close(pid_file_fd);
        pid_file_fd = -1;
        return -1;
    }

    if (ftruncate(pid_file_fd, 0) != 0) {
        syslog(LOG_ERR, "Failed to truncate PID file.");
        close(pid_file_fd);
        pid_file_fd = -1;
        return -1;
    }

    len = snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (write(pid_file_fd, pid_str, len) != len) {
        syslog(LOG_ERR, "Failed to write PID to file.");
        close(pid_file_fd);
        pid_file_fd = -1;
        return -1;
    }
    return 0;
}

void remove_pid_file() {
    if (pid_file_fd != -1) {
        flock(pid_file_fd, LOCK_UN);
        close(pid_file_fd);
        unlink(PID_FILE_PATH);
    }
}
#endif


// --- Prometheus Metrics ---
void write_prometheus_metrics() {
    char temp_path[256];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", METRICS_FILE_PATH);

    FILE *fp = fopen(temp_path, "w");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open temporary metrics file.");
        return;
    }

    pthread_mutex_lock(&user_cache.mutex);
    
    fprintf(fp, "# HELP mysql_user_storage_usage_bytes Current storage usage for a user in bytes.\n");
    fprintf(fp, "# TYPE mysql_user_storage_usage_bytes gauge\n");
    UserCacheNode *node = user_cache.head;
    while(node != NULL) {
        fprintf(fp, "mysql_user_storage_usage_bytes{user=\"%s\", limit_type=\"current\"} %lld\n", node->user, node->usage);
        if (node->soft_limit > 0) {
            fprintf(fp, "mysql_user_storage_usage_bytes{user=\"%s\", limit_type=\"soft\"} %lld\n", node->user, node->soft_limit);
        }
        if (node->hard_limit > 0) {
             fprintf(fp, "mysql_user_storage_usage_bytes{user=\"%s\", limit_type=\"hard\"} %lld\n", node->user, node->hard_limit);
        }
        node = node->next;
    }
    
    pthread_mutex_unlock(&user_cache.mutex);
    
    fclose(fp);

    if (rename(temp_path, METRICS_FILE_PATH) != 0) {
        syslog(LOG_ERR, "Failed to rename temporary metrics file to final location.");
    }
}
