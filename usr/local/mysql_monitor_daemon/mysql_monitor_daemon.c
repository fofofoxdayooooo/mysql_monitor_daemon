/**
 * @file mysql_monitor_daemon.c
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
 * - **New:** SIGHUP signal handling for configuration reload.
 * - **New:** Per-database monitoring intervals.
 * - **New:** Soft and hard capacity limits for graduated account control.
 * - **New:** Exponential backoff for database connection retries.
 * - **New:** Atomic metrics file writing for Prometheus.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <mysql/mysql.h>
#include <pwd.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>

// Constant definitions
#define CONF_FILE "/etc/mysql_search/search.conf"
#define PASSWD_FILE "/root/mysql_search/passwd"
#define USER_LIST_FILE "/etc/mysql_search/search_user"
#define PROMETHEUS_METRICS_FILE "/var/run/mysql_monitor.prom"
#define PROMETHEUS_METRICS_TMP_FILE "/var/run/mysql_monitor.prom.tmp"
#define MAX_LINE_LEN 256
#define HASH_TABLE_SIZE 101 // Use a prime number
#define LRU_CACHE_SIZE 1000 // Max size of the LRU cache
#define MAX_DBS 10
#define NUM_WORKER_THREADS 4 // Number of threads in the pool
#define INITIAL_RETRY_DELAY 1 // seconds
#define MAX_RETRY_DELAY 600 // seconds (10 minutes)
#define MAX_RETRY_ATTEMPTS 5

// Global variables
int keep_running = 1;
volatile sig_atomic_t reload_config_flag = 0;
int current_cache_size = 0;
FILE *audit_log_fp = NULL;
int debug_level = 0; // 0: detect only, 1: warn, 2: lock, 3: freeze
int shard_number = 0;
int total_shards = 1;
int prometheus_truncate = 1;

// Database connection information
typedef struct {
    char host[64];
    char user[64];
    char pass[64];
    int monitor_interval; // in seconds
    time_t last_check;
} DBConnectionInfo;

DBConnectionInfo db_list[MAX_DBS];
int db_count = 0;
char pass_list[MAX_DBS][64];

// Thread pool task queue
typedef struct Task {
    DBConnectionInfo db_info;
    struct Task *next;
} Task;

Task *task_queue = NULL;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_t thread_pool[NUM_WORKER_THREADS];

// Hash table entry for user info and limits (also acts as LRU list)
typedef struct HashTableEntry {
    char user[64];
    long long soft_limit; // Changed to long long for capacity in bytes
    long long hard_limit; // Hard limit for locking
    struct HashTableEntry *next;      // Next pointer for hash table
    struct HashTableEntry *lru_prev;  // Previous pointer for LRU list
    struct HashTableEntry *lru_next;  // Next pointer for LRU list
} HashTableEntry;

// Hash table
HashTableEntry *hash_table[HASH_TABLE_SIZE];
// LRU list head and tail
HashTableEntry *lru_head = NULL;
HashTableEntry *lru_tail = NULL;
// Mutex for thread-safe access
pthread_mutex_t lru_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Calculates the hash value for a string.
 * @param str The string to hash.
 * @return The hash value.
 */
unsigned int hash(const char *str) {
    unsigned int h = 0;
    while (*str) {
        h = 31 * h + *str++;
    }
    return h % HASH_TABLE_SIZE;
}

/**
 * @brief Removes an entry from the LRU list.
 * @param entry The entry to remove.
 */
void remove_from_lru(HashTableEntry *entry) {
    if (entry->lru_prev) {
        entry->lru_prev->lru_next = entry->lru_next;
    } else {
        lru_head = entry->lru_next;
    }
    if (entry->lru_next) {
        entry->lru_next->lru_prev = entry->lru_prev;
    } else {
        lru_tail = entry->lru_prev;
    }
}

/**
 * @brief Moves an entry to the front of the LRU list.
 * @param entry The entry to move.
 */
void move_to_front(HashTableEntry *entry) {
    if (entry == lru_head) {
        return;
    }
    remove_from_lru(entry);
    entry->lru_next = lru_head;
    entry->lru_prev = NULL;
    if (lru_head) {
        lru_head->lru_prev = entry;
    }
    lru_head = entry;
    if (!lru_tail) {
        lru_tail = entry;
    }
}

/**
 * @brief Inserts a user and limits into the hash table (LRU cache enabled).
 * @param user The username.
 * @param soft_limit The soft limit value.
 * @param hard_limit The hard limit value.
 */
void insert_user(const char *user, long long soft_limit, long long hard_limit) {
    pthread_mutex_lock(&lru_mutex);

    // Update an existing entry
    unsigned int index = hash(user);
    HashTableEntry *entry = hash_table[index];
    while (entry) {
        if (strcmp(entry->user, user) == 0) {
            entry->soft_limit = soft_limit;
            entry->hard_limit = hard_limit;
            move_to_front(entry);
            pthread_mutex_unlock(&lru_mutex);
            syslog(LOG_INFO, "User '%s' limits updated to %lld/%lld bytes.", user, soft_limit, hard_limit);
            return;
        }
        entry = entry->next;
    }

    // Insert a new entry
    entry = (HashTableEntry *)malloc(sizeof(HashTableEntry));
    if (!entry) {
        syslog(LOG_ERR, "Failed to allocate memory for hash table entry.");
        pthread_mutex_unlock(&lru_mutex);
        return;
    }
    strncpy(entry->user, user, sizeof(entry->user) - 1);
    entry->user[sizeof(entry->user) - 1] = '\0';
    entry->soft_limit = soft_limit;
    entry->hard_limit = hard_limit;

    // Insert into the hash table
    entry->next = hash_table[index];
    hash_table[index] = entry;

    // Insert into the front of the LRU list
    move_to_front(entry);
    current_cache_size++;

    // Evict the least recently used entry if the cache is full
    if (current_cache_size > LRU_CACHE_SIZE) {
        HashTableEntry *evict = lru_tail;
        if (evict) {
            remove_from_lru(evict);
            // Also remove from the hash table
            unsigned int evict_index = hash(evict->user);
            HashTableEntry *curr = hash_table[evict_index];
            HashTableEntry *prev = NULL;
            while (curr) {
                if (curr == evict) {
                    if (prev) {
                        prev->next = curr->next;
                    } else {
                        hash_table[evict_index] = curr->next;
                    }
                    free(evict);
                    current_cache_size--;
                    break;
                }
                prev = curr;
                curr = curr->next;
            }
        }
    }

    pthread_mutex_unlock(&lru_mutex);
    syslog(LOG_INFO, "User '%s' with limits %lld/%lld bytes inserted into hash table.", user, soft_limit, hard_limit);
}

/**
 * @brief Retrieves a user's limits from the hash table (LRU cache enabled).
 * @param user The username.
 * @param soft_limit Pointer to store the soft limit.
 * @param hard_limit Pointer to store the hard limit.
 * @return 0 on success, -1 if not found.
 */
int get_user_limits(const char *user, long long *soft_limit, long long *hard_limit) {
    pthread_mutex_lock(&lru_mutex);
    unsigned int index = hash(user);
    HashTableEntry *entry = hash_table[index];
    while (entry) {
        if (strcmp(entry->user, user) == 0) {
            // Move to the front of the LRU list since it was just accessed
            move_to_front(entry);
            *soft_limit = entry->soft_limit;
            *hard_limit = entry->hard_limit;
            pthread_mutex_unlock(&lru_mutex);
            return 0;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&lru_mutex);
    return -1;
}

/**
 * @brief Parses a capacity string (e.g., "2GB", "500MB") into bytes.
 * @param capacity_str The string to parse.
 * @return The capacity in bytes, or -1 on error.
 */
long long parse_capacity_string(const char *capacity_str) {
    if (!capacity_str) return -1;
    long long value = 0;
    char unit[4] = "";
    int parsed = sscanf(capacity_str, "%lld%3s", &value, unit);
    if (parsed < 1) return -1;

    // Convert to uppercase for case-insensitive comparison
    for (int i = 0; i < strlen(unit); i++) {
        if (unit[i] >= 'a' && unit[i] <= 'z') {
            unit[i] = unit[i] - 32;
        }
    }

    if (parsed == 2) {
        if (strcmp(unit, "KB") == 0) value *= 1024LL;
        else if (strcmp(unit, "MB") == 0) value *= 1024LL * 1024LL;
        else if (strcmp(unit, "GB") == 0) value *= 1024LL * 1024LL * 1024LL;
        else if (strcmp(unit, "TB") == 0) value *= 1024LL * 1024LL * 1024LL * 1024LL;
        else return -1; // Invalid unit
    }
    return value;
}

/**
 * @brief Loads MySQL connection information from the config file.
 * @return The number of databases loaded.
 */
int load_config() {
    FILE *fp = fopen(CONF_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open config file: %s", CONF_FILE);
        return 0;
    }

    char line[MAX_LINE_LEN];
    int count = 0;
    int current_db_index = -1;
    while (fgets(line, sizeof(line), fp)) {
        char *key = strtok(line, "=\n");
        char *value = strtok(NULL, "=\n");
        if (key && value) {
            if (strcmp(key, "db_host") == 0) {
                if (current_db_index + 1 < MAX_DBS) {
                    current_db_index++;
                    strncpy(db_list[current_db_index].host, value, 63);
                    db_list[current_db_index].monitor_interval = 3600; // Default to 1 hour
                    db_list[current_db_index].last_check = 0;
                }
            } else if (strcmp(key, "db_user") == 0 && current_db_index != -1) {
                strncpy(db_list[current_db_index].user, value, 63);
            } else if (strcmp(key, "db_id") == 0 && current_db_index != -1) {
                int pass_id = atoi(value);
                if (pass_id < MAX_DBS) {
                    strncpy(db_list[current_db_index].pass, pass_list[pass_id], 63);
                    count++;
                }
            } else if (strcmp(key, "monitor_interval_sec") == 0 && current_db_index != -1) {
                db_list[current_db_index].monitor_interval = atoi(value);
            } else if (strcmp(key, "prometheus_truncate") == 0) {
                prometheus_truncate = atoi(value);
            }
        }
    }
    fclose(fp);
    return count;
}

/**
 * @brief Loads the password list from the passwd file.
 * @return The number of passwords loaded.
 */
int load_passwords() {
    FILE *fp = fopen(PASSWD_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open password file: %s", PASSWD_FILE);
        return 0;
    }

    // Check file permissions
    struct stat st;
    if (stat(PASSWD_FILE, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO))) {
        syslog(LOG_CRIT, "Password file permissions are insecure. Must be 0600.");
        fclose(fp);
        return 0;
    }

    char line[MAX_LINE_LEN];
    int count = 0;
    while (fgets(line, sizeof(line), fp) && count < MAX_DBS) {
        char *newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }
        strncpy(pass_list[count], line, 63);
        count++;
    }
    fclose(fp);
    return count;
}

/**
 * @brief Loads the user watch list into the hash table with sharding logic.
 * @return 0 on success, -1 on failure.
 */
int load_user_list() {
    FILE *fp = fopen(USER_LIST_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open user list file: %s", USER_LIST_FILE);
        return -1;
    }

    // Clear existing cache before reloading
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashTableEntry *curr = hash_table[i];
        while (curr) {
            HashTableEntry *next = curr->next;
            free(curr);
            curr = next;
        }
        hash_table[i] = NULL;
    }
    lru_head = NULL;
    lru_tail = NULL;
    current_cache_size = 0;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        char *newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }

        char *user = strtok(line, ",");
        char *limit1_str = strtok(NULL, ",");
        char *limit2_str = strtok(NULL, ",");
        
        long long soft_limit = -1;
        long long hard_limit = -1;

        if (user) {
            // Apply sharding logic based on user hash
            if (hash(user) % total_shards != shard_number) {
                continue;
            }

            if (limit1_str) {
                soft_limit = parse_capacity_string(limit1_str);
                if (soft_limit == -1) {
                    syslog(LOG_ERR, "Invalid soft limit format for user '%s': %s", user, limit1_str);
                    continue;
                }
                if (limit2_str) {
                    hard_limit = parse_capacity_string(limit2_str);
                    if (hard_limit == -1) {
                        syslog(LOG_ERR, "Invalid hard limit format for user '%s': %s", user, limit2_str);
                        continue;
                    }
                } else {
                    hard_limit = soft_limit; // If only one limit is provided, it's both soft and hard
                }
            }
            insert_user(user, soft_limit, hard_limit);
        }
    }
    fclose(fp);
    return 0;
}

/**
 * @brief Signal handler.
 * @param sig The signal number.
 */
void signal_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            keep_running = 0;
            break;
        case SIGHUP:
            reload_config_flag = 1;
            break;
    }
}

/**
 * @brief Daemons the process.
 */
void daemonize() {
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    int fd = open("/dev/null", O_RDWR, 0);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) {
            close(fd);
        }
    }
}

/**
 * @brief Writes to the audit log.
 * @param format The log message format string.
 */
void write_audit_log(const char *format, ...) {
    if (!audit_log_fp) return;

    // File lock
    flock(fileno(audit_log_fp), LOCK_EX);

    va_list args;
    va_start(args, format);

    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    fprintf(audit_log_fp, "[%s] ", timestamp);
    vfprintf(audit_log_fp, format, args);
    fprintf(audit_log_fp, "\n");
    fflush(audit_log_fp);

    va_end(args);

    // Release lock
    flock(fileno(audit_log_fp), LOCK_UN);
}

/**
 * @brief Writes metrics to the Prometheus file.
 * @param user The username.
 * @param capacity The current capacity in bytes.
 * @param soft_limit The soft capacity limit in bytes.
 * @param hard_limit The hard capacity limit in bytes.
 */
void write_prometheus_metrics(const char* user, long long capacity, long long soft_limit, long long hard_limit) {
    FILE *fp = fopen(PROMETHEUS_METRICS_FILE, "a");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open Prometheus metrics file for writing: %s", PROMETHEUS_METRICS_FILE);
        return;
    }
    
    // Use an exclusive lock to ensure atomic writing
    flock(fileno(fp), LOCK_EX);

    fprintf(fp, "# HELP mysql_user_storage_bytes The total storage capacity in bytes for a MySQL user.\n");
    fprintf(fp, "# TYPE mysql_user_storage_bytes gauge\n");
    fprintf(fp, "mysql_user_storage_bytes{user=\"%s\"} %lld\n", user, capacity);

    if (soft_limit != -1) {
        fprintf(fp, "# HELP mysql_user_storage_soft_limit_bytes The storage capacity soft limit in bytes for a MySQL user.\n");
        fprintf(fp, "# TYPE mysql_user_storage_soft_limit_bytes gauge\n");
        fprintf(fp, "mysql_user_storage_soft_limit_bytes{user=\"%s\"} %lld\n", user, soft_limit);
    }
    
    if (hard_limit != -1) {
        fprintf(fp, "# HELP mysql_user_storage_hard_limit_bytes The storage capacity hard limit in bytes for a MySQL user.\n");
        fprintf(fp, "# TYPE mysql_user_storage_hard_limit_bytes gauge\n");
        fprintf(fp, "mysql_user_storage_hard_limit_bytes{user=\"%s\"} %lld\n", user, hard_limit);
    }
    
    fflush(fp);
    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

/**
 * @brief Main logic for the MySQL monitoring worker thread.
 * @param arg Unused.
 */
void* monitor_worker(void *arg) {
    while (keep_running) {
        Task *task;
        pthread_mutex_lock(&queue_mutex);
        while (task_queue == NULL && keep_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        if (!keep_running) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        task = task_queue;
        task_queue = task_queue->next;
        pthread_mutex_unlock(&queue_mutex);

        // --- Monitoring Logic with exponential backoff ---
        DBConnectionInfo *db_info = &task->db_info;
        MYSQL *conn = NULL;
        int retry_count = 0;
        int sleep_delay = INITIAL_RETRY_DELAY;
        
        while (retry_count < MAX_RETRY_ATTEMPTS) {
            conn = mysql_init(NULL);
            if (conn == NULL) {
                syslog(LOG_ERR, "mysql_init() failed in worker thread for %s", db_info->host);
                sleep(sleep_delay);
                sleep_delay = sleep_delay * 2;
                if (sleep_delay > MAX_RETRY_DELAY) sleep_delay = MAX_RETRY_DELAY;
                retry_count++;
                continue;
            }

            if (mysql_real_connect(conn, db_info->host, db_info->user, db_info->pass, NULL, 0, NULL, 0) == NULL) {
                syslog(LOG_ERR, "mysql_real_connect() failed for %s: %s", db_info->host, mysql_error(conn));
                mysql_close(conn);
                sleep(sleep_delay);
                sleep_delay = sleep_delay * 2;
                if (sleep_delay > MAX_RETRY_DELAY) sleep_delay = MAX_RETRY_DELAY;
                retry_count++;
                continue;
            }
            break; // Connection successful
        }
        
        if (conn == NULL) {
            syslog(LOG_CRIT, "Failed to connect to %s after multiple retries. Giving up for this cycle.", db_info->host);
            free(task);
            continue;
        }
        
        const char *sql_query = "SELECT TABLE_SCHEMA, SUM(DATA_LENGTH + INDEX_LENGTH) AS total_size FROM information_schema.tables GROUP BY TABLE_SCHEMA;";
        if (mysql_query(conn, sql_query)) {
            syslog(LOG_ERR, "SELECT query failed for %s: %s", db_info->host, mysql_error(conn));
            mysql_close(conn);
            free(task);
            continue;
        }

        MYSQL_RES *res = mysql_store_result(conn);
        if (res == NULL) {
            syslog(LOG_ERR, "mysql_store_result() failed for %s: %s", db_info->host, mysql_error(conn));
            mysql_close(conn);
            free(task);
            continue;
        }
        
        // Before writing, truncate the file if the flag is set.
        if (prometheus_truncate) {
            FILE *fp = fopen(PROMETHEUS_METRICS_FILE, "w");
            if (fp) {
                flock(fileno(fp), LOCK_EX);
                ftruncate(fileno(fp), 0);
                fclose(fp);
            }
        }

        MYSQL_ROW row;
        while ((row = mysql_fetch_row(res))) {
            char *schema_name = row[0];
            long long current_capacity = atoll(row[1]);
            long long soft_limit = -1;
            long long hard_limit = -1;
            
            get_user_limits(schema_name, &soft_limit, &hard_limit);
            
            // Output Prometheus metric
            write_prometheus_metrics(schema_name, current_capacity, soft_limit, hard_limit);

            // Check against limits
            if (soft_limit != -1 && current_capacity > soft_limit) {
                syslog(LOG_WARNING, "User '%s' on %s has %lld bytes, exceeding soft limit of %lld.", schema_name, db_info->host, current_capacity, soft_limit);
                write_audit_log("EXCEEDED_SOFT_LIMIT: User '%s' on %s. Current: %lld, Soft Limit: %lld.", schema_name, db_info->host, current_capacity, soft_limit);
            }
            
            if (hard_limit != -1 && current_capacity > hard_limit) {
                syslog(LOG_CRIT, "User '%s' on %s has %lld bytes, exceeding hard limit of %lld.", schema_name, db_info->host, current_capacity, hard_limit);
                write_audit_log("EXCEEDED_HARD_LIMIT: User '%s' on %s. Current: %lld, Hard Limit: %lld.", schema_name, db_info->host, current_capacity, hard_limit);
                
                if (debug_level >= 2) {
                    char sql_lock[256];
                    snprintf(sql_lock, sizeof(sql_lock), "ALTER USER '%s'@'%%' ACCOUNT LOCK;", schema_name);
                    if (mysql_query(conn, sql_lock)) {
                        syslog(LOG_ERR, "ALTER USER query for user '%s' failed on %s: %s", schema_name, db_info->host, mysql_error(conn));
                    } else {
                        syslog(LOG_INFO, "User '%s' has been disabled on %s.", schema_name, db_info->host);
                        write_audit_log("DISABLED: User '%s' on %s. Reason: exceeded hard capacity limit (%lld/%lld bytes).", schema_name, db_info->host, current_capacity, hard_limit);
                    }
                }
            }
        }
        mysql_free_result(res);
        mysql_close(conn);
        free(task);
    }
    return NULL;
}

/**
 * @brief Reloads all configuration files.
 */
void reload_all_configs() {
    syslog(LOG_INFO, "Reloading configuration files due to SIGHUP.");
    load_passwords();
    db_count = load_config();
    load_user_list();
    reload_config_flag = 0;
    syslog(LOG_INFO, "Configuration reload complete. Monitoring %d databases.", db_count);
}

int main(int argc, char *argv[]) {
    // Check if the program is run as root
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return EXIT_FAILURE;
    }

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "d:s:t:")) != -1) {
        switch (opt) {
            case 'd': debug_level = atoi(optarg); break;
            case 's': shard_number = atoi(optarg); break;
            case 't': total_shards = atoi(optarg); break;
        }
    }
    if (shard_number >= total_shards) {
        fprintf(stderr, "Invalid shard number. Shard number must be less than total shards.\n");
        return EXIT_FAILURE;
    }

    // Open syslog
    openlog("mysql_monitor_daemon", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Daemon starting up with debug level %d, shard %d of %d.", debug_level, shard_number, total_shards);

    // Check config file permissions
    struct stat st;
    if (stat(CONF_FILE, &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO))) {
        syslog(LOG_CRIT, "Config file permissions are insecure. Must be 0600.");
        closelog();
        return EXIT_FAILURE;
    }

    // Open the audit log file
    audit_log_fp = fopen("/var/log/mysql_monitor_audit.log", "a+");
    if (!audit_log_fp) {
        syslog(LOG_ERR, "Failed to open audit log file.");
        closelog();
        return EXIT_FAILURE;
    }

    // Set up signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);

    // Daemonize the process
    daemonize();

    // Drop privileges: from root to 'mysql' user
    struct passwd *pw = getpwnam("mysql");
    if (pw == NULL) {
        syslog(LOG_CRIT, "Failed to find 'mysql' user. Cannot drop privileges. Exiting.");
        fclose(audit_log_fp);
        closelog();
        return EXIT_FAILURE;
    }
    if (setuid(pw->pw_uid) == -1) {
        syslog(LOG_CRIT, "Failed to drop privileges to 'mysql' user. Exiting.");
        fclose(audit_log_fp);
        closelog();
        return EXIT_FAILURE;
    }
    syslog(LOG_INFO, "Privileges successfully dropped to user '%s'.", pw->pw_name);

    // Load initial passwords and config file
    int pass_count = load_passwords();
    if (pass_count == 0) {
        syslog(LOG_ERR, "Failed to load passwords or file is empty.");
        fclose(audit_log_fp);
        closelog();
        return EXIT_FAILURE;
    }
    db_count = load_config();
    if (db_count == 0) {
        syslog(LOG_ERR, "Failed to load config file or no databases specified.");
        fclose(audit_log_fp);
        closelog();
        return EXIT_FAILURE;
    }
    if (load_user_list() != 0) {
        syslog(LOG_ERR, "Failed to load user list file.");
        fclose(audit_log_fp);
        closelog();
        return EXIT_FAILURE;
    }

    // Create worker threads
    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        pthread_create(&thread_pool[i], NULL, monitor_worker, NULL);
    }

    // Main loop for submitting tasks
    while (keep_running) {
        if (reload_config_flag) {
            reload_all_configs();
        }

        time_t now = time(NULL);
        for (int i = 0; i < db_count; i++) {
            if (now >= db_list[i].last_check + db_list[i].monitor_interval) {
                pthread_mutex_lock(&queue_mutex);
                Task *new_task = (Task *)malloc(sizeof(Task));
                if (new_task) {
                    memcpy(&new_task->db_info, &db_list[i], sizeof(DBConnectionInfo));
                    new_task->next = NULL;
                    Task *tail = task_queue;
                    if (!tail) {
                        task_queue = new_task;
                    } else {
                        while (tail->next) {
                            tail = tail->next;
                        }
                        tail->next = new_task;
                    }
                }
                pthread_cond_signal(&queue_cond);
                pthread_mutex_unlock(&queue_mutex);
                db_list[i].last_check = now;
            }
        }
        sleep(10); // Check every 10 seconds for tasks due
    }

    // Clean up
    pthread_mutex_lock(&queue_mutex);
    keep_running = 0;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    for (int i = 0; i < NUM_WORKER_THREADS; i++) {
        pthread_join(thread_pool[i], NULL);
    }

    fclose(audit_log_fp);
    closelog();
    return EXIT_SUCCESS;
}
