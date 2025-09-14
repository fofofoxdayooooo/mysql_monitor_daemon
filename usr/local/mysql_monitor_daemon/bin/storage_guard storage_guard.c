/*
 * storage_guard storage_guard.c - External daemon for MySQL/MariaDB storage quota enforcement
 *
 * Features:
 * - Runs as a daemon on Linux/FreeBSD
 * - INI-style configuration files
 * - User limits inline ([limits]) or external file ([users])
 * - DB version detection (MySQL / MariaDB legacy/new)
 * - Periodic monitoring with threshold_trigger
 * - Soft/Hard limit detection with LOCK + KILL USER
 * - Prometheus metrics output with extended labels (db_type, host, etc.)
 * - Log level control (DEBUG/INFO/WARN/ERROR)
 * - Supports multiple configurable schema naming patterns
 * - Thread pool implementation to limit concurrent DB connections.
 *
 * Improvements in this version:
 * - **NEW:** Implemented DB connection pooling to reduce connection overhead.
 * - **NEW:** Added 'use_connection_pool' option to enable/disable pooling.
 * - **NEW:** Dynamically allocate ThreadArgs and free them in the thread, ensuring a safe lifecycle.
 * - **NEW:** Added a 'connection_pool_size' option to configure the pool size.
 * - **NEW:** Corrected an issue where log messages could cause a mutex deadlock during initialization.
 * - **NEW:** Made schema pattern parsing more robust by defaulting to '%s' if the pattern is empty.
 * - **NEW:** Added 'connection_pool_size' to Prometheus metrics for better monitoring.
 * - Implemented a secure password buffer zeroing function to prevent compiler optimization.
 * - Refactored config parsing to support atomic reload on SIGHUP
 * - Added a dedicated function to read the password file, including permission checks (0600)
 * - Enhanced logging for unknown log levels and file-based logging
 * - Added a configurable schema naming pattern
 * - Added a --foreground option for easier debugging and systemd management
 * - Added db_type and host to Prometheus metrics labels for better monitoring
 * - Can write logs to a file instead of syslog
 * - Added a --dry-run option to perform checks without making changes
 *
 * Compile:
 * On Linux: gcc -o storage_guard storage_guard.c -lmysqlclient -lpthread
 * On FreeBSD: gcc -o storage_guard storage_guard.c -lmysqlclient -lutil -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <mysql/mysql.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>

#ifdef __FreeBSD__
#include <libutil.h>
#include <sys/param.h>
#else
#include <sys/file.h>
#include <sys/prctl.h>
#endif

// -----------------------------
// Config and user structures
// -----------------------------

#define MAX_USERS 1024
#define MAX_USER_NAME 64
#define PATH_BUFFER_SIZE 256
#define NAME_BUFFER_SIZE 64
#define MAX_SECTION_NAME 64

typedef struct {
    char user[MAX_USER_NAME];
    long long soft_limit;
    long long hard_limit;
    int soft_count;
    int hard_count;
    long long last_usage;
    int status; // 0=ok,1=soft,2=hard
} UserLimit;

typedef struct {
    char log_level[16];
    char log_file[PATH_BUFFER_SIZE];
    int syslog_on_error;
    int check_interval;
    char metrics_file[PATH_BUFFER_SIZE];
    int metrics_buffer_size;
    int kill_on_hard_limit;
    char user_limits_file[PATH_BUFFER_SIZE];
    int threshold_trigger;
    char schema_patterns[256];
    bool use_threads;
    int max_threads;
    bool use_connection_pool;
    int connection_pool_size;

    char db_host[128];
    int db_port;
    char db_user[NAME_BUFFER_SIZE];
    char db_pass_file[PATH_BUFFER_SIZE];
    char db_type[16];
    
    char daemon_user[NAME_BUFFER_SIZE];
    char daemon_group[NAME_BUFFER_SIZE];
} Config;

static Config config;
static UserLimit user_limits[MAX_USERS];
static int user_limit_count = 0;

static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t reload_config_flag = 0;

#ifdef __FreeBSD__
static struct pidfh *pfh;
#else
static int pid_fd = -1;
#endif

static int dry_run = 0;
static FILE *log_fp = NULL;

static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// -----------------------------
// Thread pool structures
// -----------------------------
typedef struct {
    void (*function)(void*);
    void *argument;
} task_t;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t notify;
    pthread_t *threads;
    task_t *queue;
    int thread_count;
    int queue_size;
    int head;
    int tail;
    int count;
    int shutdown;
} thread_pool_t;

static thread_pool_t *pool = NULL;

// -----------------------------
// Connection pool structures
// -----------------------------
typedef struct {
    MYSQL *conn;
    bool is_in_use;
} db_connection_t;

static db_connection_t *connection_pool = NULL;
static pthread_mutex_t conn_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t conn_pool_cond = PTHREAD_COND_INITIALIZER;
static int connections_in_pool = 0;


// -----------------------------
// Security related functions
// -----------------------------
// Secure memory clearing function to prevent compiler optimization
void secure_zero(void *s, size_t n) {
    volatile char *p = (volatile char *)s;
    while (n--) {
        *p++ = 0;
    }
}

// -----------------------------
// Logging with level
// -----------------------------
typedef enum {
    LOG_DEBUG_LVL = 0,
    LOG_INFO_LVL  = 1,
    LOG_WARN_LVL  = 2,
    LOG_ERROR_LVL = 3
} LogLevel;

static LogLevel current_log_level = LOG_INFO_LVL;

static void set_log_level(const char *level) {
    if(strcasecmp(level,"DEBUG")==0) current_log_level = LOG_DEBUG_LVL;
    else if(strcasecmp(level,"INFO")==0) current_log_level = LOG_INFO_LVL;
    else if(strcasecmp(level,"WARN")==0) current_log_level = LOG_WARN_LVL;
    else if(strcasecmp(level,"ERROR")==0) current_log_level = LOG_ERROR_LVL;
    else {
        current_log_level = LOG_INFO_LVL;
    }
}

static void log_msg(LogLevel lvl, const char *fmt, ...) {
    pthread_mutex_lock(&log_mutex);
    if(lvl < current_log_level) {
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    va_list ap;
    va_start(ap, fmt);
    
    // Log to file if configured
    if (log_fp) {
        char buffer[1024];
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
        
        const char *level_str = "INFO";
        switch(lvl) {
            case LOG_DEBUG_LVL: level_str = "DEBUG"; break;
            case LOG_INFO_LVL:  level_str = "INFO";  break;
            case LOG_WARN_LVL:  level_str = "WARN"; break;
            case LOG_ERROR_LVL: level_str = "ERROR"; break;
        }

        snprintf(buffer, sizeof(buffer), "[%s] [%s] ", time_str, level_str);
        size_t offset = strlen(buffer);
        vsnprintf(buffer + offset, sizeof(buffer) - offset, fmt, ap);
        strcat(buffer, "\n");
        fputs(buffer, log_fp);
        fflush(log_fp);
    }
    
    // Log to syslog if required
    if (config.syslog_on_error && lvl == LOG_ERROR_LVL) {
        int syslog_lvl = LOG_ERR;
        vsyslog(syslog_lvl, fmt, ap);
    }
    
    // If no log file is configured, always use syslog
    if (log_fp == NULL) {
        int syslog_lvl = LOG_INFO;
        switch(lvl) {
            case LOG_DEBUG_LVL: syslog_lvl = LOG_DEBUG; break;
            case LOG_INFO_LVL:  syslog_lvl = LOG_INFO;  break;
            case LOG_WARN_LVL:  syslog_lvl = LOG_WARNING; break;
            case LOG_ERROR_LVL: syslog_lvl = LOG_ERR; break;
        }
        vsyslog(syslog_lvl, fmt, ap);
    }
    
    va_end(ap);
    pthread_mutex_unlock(&log_mutex);
}

// -----------------------------
// Signal handling
// -----------------------------
static void signal_handler(int sig) {
    switch(sig) {
        case SIGHUP:
            reload_config_flag = 1;
            log_msg(LOG_INFO_LVL,"SIGHUP received: reload configuration");
            break;
        case SIGINT:
        case SIGTERM:
            keep_running = 0;
            log_msg(LOG_INFO_LVL,"Termination signal received");
            break;
    }
}

// -----------------------------
// Simple INI parser
// -----------------------------
static void trim_whitespace(char *s) {
    if (!s || !*s) return;
    char *end;
    while(isspace((unsigned char)*s)) s++;
    if(*s == 0) return;
    end = s + strlen(s) - 1;
    while(end >= s && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

static int parse_config_file(const char *path, Config *cfg, UserLimit *limits, int *limit_count, int user_file_mode) {
    FILE *fp = fopen(path, "r");
    if(!fp) {
        log_msg(LOG_ERROR_LVL,"Failed to open config file %s: %s", path, strerror(errno));
        return -1;
    }
    char line[512];
    char section[MAX_SECTION_NAME] = "";
    if (!user_file_mode) {
        memset(cfg, 0, sizeof(Config));
        // Set default values
        strncpy(cfg->log_level, "INFO", sizeof(cfg->log_level) - 1);
        cfg->syslog_on_error = 1;
        cfg->check_interval = 60;
        cfg->kill_on_hard_limit = 1;
        cfg->threshold_trigger = 3;
        strncpy(cfg->db_host, "localhost", sizeof(cfg->db_host) - 1);
        cfg->db_port = 3306;
        strncpy(cfg->db_type, "mysql", sizeof(cfg->db_type) - 1);
        strncpy(cfg->schema_patterns, "%s", sizeof(cfg->schema_patterns) - 1);
        cfg->metrics_buffer_size = 4096; // 4KB default
        cfg->use_threads = false;
        cfg->max_threads = 16;
        cfg->use_connection_pool = false;
        cfg->connection_pool_size = 10;
    }
    memset(limits, 0, sizeof(UserLimit) * MAX_USERS);
    *limit_count = 0;

    while(fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        if(line[0] == '#' || strlen(line) == 0) continue;
        if(line[0] == '[') {
            if(sscanf(line, "[%63[^]]", section) != 1) {
                log_msg(LOG_WARN_LVL, "Invalid section header in %s: %s", path, line);
                continue;
            }
            continue;
        }
        
        char key[128], value[256];
        if(sscanf(line, "%127[^=]=%255[^\n]", key, value) == 2) {
            trim_whitespace(key);
            trim_whitespace(value);
            
            if(!user_file_mode) {
                if(strcmp(section, "general")==0) {
                    if(strcmp(key,"log_level")==0) { strncpy(cfg->log_level,value,sizeof(cfg->log_level)-1); }
                    else if(strcmp(key,"log_file")==0) { strncpy(cfg->log_file,value,sizeof(cfg->log_file)-1); }
                    else if(strcmp(key,"syslog_on_error")==0) cfg->syslog_on_error=(strcasecmp(value,"yes")==0);
                    else if(strcmp(key,"check_interval")==0) cfg->check_interval=atoi(value);
                    else if(strcmp(key,"metrics_file")==0) { strncpy(cfg->metrics_file,value,sizeof(cfg->metrics_file)-1); }
                    else if(strcmp(key,"metrics_buffer_size")==0) cfg->metrics_buffer_size=atoi(value);
                    else if(strcmp(key,"kill_on_hard_limit")==0) cfg->kill_on_hard_limit=(strcasecmp(value,"yes")==0);
                    else if(strcmp(key,"user_limits_file")==0) { strncpy(cfg->user_limits_file,value,sizeof(cfg->user_limits_file)-1); }
                    else if(strcmp(key,"threshold_trigger")==0) cfg->threshold_trigger=atoi(value);
                    else if(strcmp(key,"daemon_user")==0) { strncpy(cfg->daemon_user,value,sizeof(cfg->daemon_user)-1); }
                    else if(strcmp(key,"daemon_group")==0) { strncpy(cfg->daemon_group,value,sizeof(cfg->daemon_group)-1); }
                    else if(strcmp(key,"schema_patterns")==0) { strncpy(cfg->schema_patterns,value,sizeof(cfg->schema_patterns)-1); }
                    else if(strcmp(key,"use_threads")==0) cfg->use_threads=(strcasecmp(value,"yes")==0);
                    else if(strcmp(key,"max_threads")==0) cfg->max_threads=atoi(value);
                    else if(strcmp(key,"use_connection_pool")==0) cfg->use_connection_pool=(strcasecmp(value,"yes")==0);
                    else if(strcmp(key,"connection_pool_size")==0) cfg->connection_pool_size=atoi(value);
                } else if(strcmp(section,"database")==0) {
                    if(strcmp(key,"host")==0) { strncpy(cfg->db_host,value,sizeof(cfg->db_host)-1); }
                    else if(strcmp(key,"port")==0) cfg->db_port=atoi(value);
                    else if(strcmp(key,"user")==0) { strncpy(cfg->db_user,value,sizeof(cfg->db_user)-1); }
                    else if(strcmp(key,"password_file")==0) { strncpy(cfg->db_pass_file,value,sizeof(cfg->db_pass_file)-1); }
                    else if(strcmp(key,"type")==0) { strncpy(cfg->db_type,value,sizeof(cfg->db_type)-1); }
                } else if(strcmp(section,"limits")==0) {
                    if(*limit_count < MAX_USERS) {
                        UserLimit *ul=&limits[(*limit_count)++];
                        strncpy(ul->user, key, sizeof(ul->user)-1);
                        ul->user[sizeof(ul->user)-1] = '\0';
                        sscanf(value,"%lld , %lld",&ul->soft_limit,&ul->hard_limit);
                    }
                }
            } else {
                if(strcmp(section,"users")==0 && *limit_count<MAX_USERS) {
                    UserLimit *ul=&limits[(*limit_count)++];
                    strncpy(ul->user, key, sizeof(ul->user)-1);
                    ul->user[sizeof(ul->user)-1] = '\0';
                    sscanf(value,"%lld , %lld",&ul->soft_limit,&ul->hard_limit);
                }
            }
        }
    }
    fclose(fp);
    if (strlen(cfg->schema_patterns) == 0) {
        strncpy(cfg->schema_patterns, "%s", sizeof(cfg->schema_patterns)-1);
    }
    return 0;
}

static int load_config() {
    Config temp_config;
    UserLimit temp_user_limits[MAX_USERS];
    int temp_user_limit_count = 0;

    if(parse_config_file("/etc/storage_guard.conf", &temp_config, temp_user_limits, &temp_user_limit_count, 0)!=0) return -1;
    if(strlen(temp_config.user_limits_file)>0) {
        if (parse_config_file(temp_config.user_limits_file, &temp_config, temp_user_limits, &temp_user_limit_count, 1) != 0) {
            log_msg(LOG_ERROR_LVL, "Failed to load user limits file %s. Using main config limits.", temp_config.user_limits_file);
        }
    }
    
    pthread_mutex_lock(&config_mutex);
    // Close old log file if it exists, and open new one if specified
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
    if (strlen(temp_config.log_file) > 0) {
        log_fp = fopen(temp_config.log_file, "a");
        if (!log_fp) {
            // Can't use log_msg here, as it may cause a deadlock on the mutex.
            fprintf(stderr, "Failed to open log file %s, falling back to syslog: %s\n", temp_config.log_file, strerror(errno));
        }
    }
    
    // Atomically swap the config
    memcpy(&config, &temp_config, sizeof(Config));
    memcpy(user_limits, temp_user_limits, sizeof(UserLimit) * MAX_USERS);
    user_limit_count = temp_user_limit_count;
    set_log_level(config.log_level);
    
    log_msg(LOG_INFO_LVL,"Loaded %d user limits", user_limit_count);
    pthread_mutex_unlock(&config_mutex);
    return 0;
}

static int get_db_password(const char *path, char *buffer, size_t buffer_size) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if ((st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != S_IRUSR) {
            log_msg(LOG_ERROR_LVL, "Password file %s has insecure permissions. Must be 0600.", path);
            return -1;
        }
    } else {
        log_msg(LOG_ERROR_LVL, "Failed to stat password file %s: %s", path, strerror(errno));
        return -1;
    }

    FILE *pf=fopen(path, "r");
    if(!pf) {
        log_msg(LOG_ERROR_LVL, "Failed to open password file %s: %s", path, strerror(errno));
        return -1;
    }
    
    if(fgets(buffer, buffer_size, pf)) {
        buffer[strcspn(buffer,"\n")]=0;
    } else {
        log_msg(LOG_WARN_LVL, "Password file is empty or read failed: %s", path);
        buffer[0] = '\0';
    }
    fclose(pf);
    return 0;
}


// -----------------------------
// DB helpers
// -----------------------------
typedef enum {
    DB_TYPE_UNKNOWN,
    DB_TYPE_MYSQL,
    DB_TYPE_MARIADB_LEGACY,
    DB_TYPE_MARIADB_NEW
} DBType;

static DBType detect_db_version(MYSQL *conn) {
    const char *ver=mysql_get_server_info(conn);
    if(!ver) return DB_TYPE_UNKNOWN;
    if(strstr(ver,"MariaDB")) {
        int major=0,minor=0;
        if(sscanf(ver,"%d.%d",&major,&minor)==2) {
            if(major==10 && minor<=3) return DB_TYPE_MARIADB_LEGACY;
            else return DB_TYPE_MARIADB_NEW;
        }
        log_msg(LOG_WARN_LVL, "Could not parse MariaDB version string: %s", ver);
        return DB_TYPE_MARIADB_NEW; // Assume new for safety
    } else return DB_TYPE_MYSQL;
}

static long long get_user_usage(MYSQL *conn, const char *user) {
    char query[512];
    char schema_name[NAME_BUFFER_SIZE];
    
    pthread_mutex_lock(&config_mutex);
    char *patterns_copy = strdup(config.schema_patterns);
    pthread_mutex_unlock(&config_mutex);
    
    if (!patterns_copy) return -1;
    
    long long total_usage = 0;
    char *token, *rest = patterns_copy;
    int schemas_found = 0;

    while ((token = strtok_r(rest, ",", &rest))) {
        snprintf(schema_name, sizeof(schema_name), token, user);
        
        snprintf(query, sizeof(query),
                 "SELECT IFNULL(SUM(data_length+index_length), 0) "
                 "FROM information_schema.tables WHERE table_schema = '%s';", schema_name);
                 
        if(mysql_query(conn,query)) {
            log_msg(LOG_DEBUG_LVL,"Usage query failed for %s (schema %s): %s", user, schema_name, mysql_error(conn));
        } else {
            MYSQL_RES *res=mysql_store_result(conn);
            if(res) {
                MYSQL_ROW row=mysql_fetch_row(res);
                if(row && row[0]) {
                    total_usage += atoll(row[0]);
                    schemas_found++;
                }
                mysql_free_result(res);
            }
        }
    }

    free(patterns_copy);
    if (schemas_found == 0) {
        log_msg(LOG_ERROR_LVL, "No schemas found for user %s with patterns: %s", user, config.schema_patterns);
        return -1;
    }
    return total_usage;
}

static void lock_user_account(MYSQL *conn,const char *user,DBType type) {
    if (dry_run) {
        log_msg(LOG_WARN_LVL, "DRY-RUN: Would have locked user account %s.", user);
        return;
    }
    char query[512]; int rc=0;
    switch(type) {
        case DB_TYPE_MYSQL:
        case DB_TYPE_MARIADB_NEW:
            snprintf(query,sizeof(query),"ALTER USER '%s'@'%%' ACCOUNT LOCK;",user);
            rc=mysql_query(conn,query);
            break;
        case DB_TYPE_MARIADB_LEGACY:
            snprintf(query,sizeof(query),"REVOKE ALL PRIVILEGES, GRANT OPTION FROM '%s'@'%%';",user);
            rc=mysql_query(conn,query);
            if(rc==0) {
                snprintf(query,sizeof(query),"UPDATE mysql.user SET account_locked='Y' WHERE user='%s';",user);
                rc=mysql_query(conn,query);
            }
            if(rc==0) rc=mysql_query(conn,"FLUSH PRIVILEGES;");
            break;
        default:
            log_msg(LOG_ERROR_LVL,"Unknown DB type, cannot lock %s",user);
            return;
    }
    if(rc!=0) log_msg(LOG_ERROR_LVL,"Lock failed for %s: %s",user,mysql_error(conn));
    else log_msg(LOG_WARN_LVL,"User %s locked",user);
}

static void kill_user_sessions(MYSQL *conn,const char *user) {
    if (dry_run) {
        log_msg(LOG_WARN_LVL, "DRY-RUN: Would have killed sessions for user %s.", user);
        return;
    }
    char query[256];
    snprintf(query,sizeof(query),"SELECT id FROM information_schema.processlist WHERE user='%s';", user);
    if(mysql_query(conn, query)) {
        log_msg(LOG_ERROR_LVL, "Failed to get processlist for %s: %s", user, mysql_error(conn));
        return;
    }

    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) {
        log_msg(LOG_ERROR_LVL, "Failed to store processlist result for %s: %s", user, mysql_error(conn));
        return;
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        char kill_query[64];
        if (row[0]) {
            snprintf(kill_query, sizeof(kill_query), "KILL %s;", row[0]);
            if (mysql_query(conn, kill_query) != 0) {
                log_msg(LOG_ERROR_LVL, "Failed to kill connection %s for user %s: %s", row[0], user, mysql_error(conn));
            } else {
                log_msg(LOG_WARN_LVL, "Killed session %s for user %s", row[0], user);
            }
        }
    }
    mysql_free_result(res);
}

// -----------------------------
// Prometheus output
// -----------------------------
static void write_prometheus_metrics(const char *db_type, const char *db_host) {
    pthread_mutex_lock(&config_mutex);
    if(strlen(config.metrics_file)==0) {
        pthread_mutex_unlock(&config_mutex);
        return;
    }
    char tmpfile[PATH_BUFFER_SIZE+4]; snprintf(tmpfile,sizeof(tmpfile),"%s.tmp",config.metrics_file);
    FILE *fp=fopen(tmpfile,"w");
    if(!fp) {
        log_msg(LOG_ERROR_LVL,"Metrics file open failed: %s", strerror(errno));
        pthread_mutex_unlock(&config_mutex);
        return;
    }

    if (config.metrics_buffer_size > 0) {
        char *buffer = malloc(config.metrics_buffer_size);
        if (buffer) {
            setvbuf(fp, buffer, _IOFBF, config.metrics_buffer_size);
        } else {
            log_msg(LOG_WARN_LVL, "Failed to allocate metrics buffer, using default buffering.");
        }
    }
    
    fprintf(fp,"# HELP storage_guard_user_usage_bytes Current usage per user\n");
    fprintf(fp,"# TYPE storage_guard_user_usage_bytes gauge\n");
    for(int i=0;i<user_limit_count;i++)
        fprintf(fp,"storage_guard_user_usage_bytes{user=\"%s\",db_type=\"%s\",db_host=\"%s\"} %lld\n",
                user_limits[i].user, db_type, db_host, (long long)user_limits[i].last_usage);
    
    fprintf(fp,"# HELP storage_guard_user_soft_limit_bytes Soft limit per user\n");
    fprintf(fp,"# TYPE storage_guard_user_soft_limit_bytes gauge\n");
    for(int i=0;i<user_limit_count;i++)
        fprintf(fp,"storage_guard_user_soft_limit_bytes{user=\"%s\",db_type=\"%s\",db_host=\"%s\"} %lld\n",
                user_limits[i].user, db_type, db_host, (long long)user_limits[i].soft_limit);
    
    fprintf(fp,"# HELP storage_guard_user_hard_limit_bytes Hard limit per user\n");
    fprintf(fp,"# TYPE storage_guard_user_hard_limit_bytes gauge\n");
    for(int i=0;i<user_limit_count;i++)
        fprintf(fp,"storage_guard_user_hard_limit_bytes{user=\"%s\",db_type=\"%s\",db_host=\"%s\"} %lld\n",
                user_limits[i].user, db_type, db_host, (long long)user_limits[i].hard_limit);
    
    fprintf(fp,"# HELP storage_guard_user_status Status 0=ok,1=soft,2=hard\n");
    fprintf(fp,"# TYPE storage_guard_user_status gauge\n");
    for(int i=0;i<user_limit_count;i++)
        fprintf(fp,"storage_guard_user_status{user=\"%s\",db_type=\"%s\",db_host=\"%s\"} %d\n",
                user_limits[i].user, db_type, db_host, user_limits[i].status);

    fprintf(fp,"# HELP storage_guard_connection_pool_size The configured size of the connection pool\n");
    fprintf(fp,"# TYPE storage_guard_connection_pool_size gauge\n");
    fprintf(fp,"storage_guard_connection_pool_size{db_type=\"%s\",db_host=\"%s\"} %d\n",
            db_type, db_host, config.connection_pool_size);
    
    fclose(fp);
    if(rename(tmpfile,config.metrics_file) != 0) {
        log_msg(LOG_ERROR_LVL,"Failed to rename metrics file: %s", strerror(errno));
    }
    pthread_mutex_unlock(&config_mutex);
}

// -----------------------------
// Thread pool implementation
// -----------------------------
static void *thread_pool_worker(void *arg) {
    thread_pool_t *pool = (thread_pool_t *)arg;
    task_t task;

    while (1) {
        pthread_mutex_lock(&pool->lock);
        while (pool->count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->notify, &pool->lock);
        }
        
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }

        task = pool->queue[pool->head];
        pool->head = (pool->head + 1) % pool->queue_size;
        pool->count--;
        
        pthread_mutex_unlock(&pool->lock);
        
        // Execute the task
        task.function(task.argument);
    }
    
    return NULL;
}

static thread_pool_t *thread_pool_create(int thread_count, int queue_size) {
    if (thread_count <= 0 || queue_size <= 0) return NULL;
    
    thread_pool_t *pool = (thread_pool_t *)malloc(sizeof(thread_pool_t));
    if (!pool) return NULL;
    
    memset(pool, 0, sizeof(thread_pool_t));
    
    pool->thread_count = thread_count;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = 0;
    
    pool->threads = (pthread_t *)malloc(sizeof(pthread_t) * thread_count);
    pool->queue = (task_t *)malloc(sizeof(task_t) * queue_size);
    
    if (!pool->threads || !pool->queue || pthread_mutex_init(&pool->lock, NULL) != 0 || pthread_cond_init(&pool->notify, NULL) != 0) {
        // Cleanup on failure
        if (pool->threads) free(pool->threads);
        if (pool->queue) free(pool->queue);
        free(pool);
        return NULL;
    }
    
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, thread_pool_worker, (void *)pool) != 0) {
            log_msg(LOG_ERROR_LVL, "Failed to create thread pool thread.");
            pool->shutdown = 1;
            break;
        }
    }
    
    return pool;
}

static int thread_pool_add_task(thread_pool_t *pool, void (*function)(void*), void *argument) {
    pthread_mutex_lock(&pool->lock);
    
    if (pool->shutdown || pool->count == pool->queue_size) {
        pthread_mutex_unlock(&pool->lock);
        return -1;
    }
    
    pool->queue[pool->tail].function = function;
    pool->queue[pool->tail].argument = argument;
    pool->tail = (pool->tail + 1) % pool->queue_size;
    pool->count++;
    
    pthread_cond_signal(&pool->notify);
    pthread_mutex_unlock(&pool->lock);
    
    return 0;
}

static void thread_pool_destroy(thread_pool_t *pool) {
    if (pool == NULL) return;
    
    pthread_mutex_lock(&pool->lock);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->notify);
    pthread_mutex_unlock(&pool->lock);
    
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    free(pool->threads);
    free(pool->queue);
    
    pthread_mutex_destroy(&pool->lock);
    pthread_cond_destroy(&pool->notify);
    
    free(pool);
}


// -----------------------------
// Connection pool implementation
// -----------------------------
static MYSQL* get_conn_from_pool() {
    pthread_mutex_lock(&conn_pool_mutex);
    MYSQL *conn = NULL;
    while (!conn) {
        for (int i = 0; i < connections_in_pool; i++) {
            if (!connection_pool[i].is_in_use) {
                connection_pool[i].is_in_use = true;
                conn = connection_pool[i].conn;
                break;
            }
        }
        if (!conn) {
            pthread_cond_wait(&conn_pool_cond, &conn_pool_mutex);
        }
    }
    pthread_mutex_unlock(&conn_pool_mutex);
    return conn;
}

static void return_conn_to_pool(MYSQL *conn) {
    pthread_mutex_lock(&conn_pool_mutex);
    for (int i = 0; i < connections_in_pool; i++) {
        if (connection_pool[i].conn == conn) {
            connection_pool[i].is_in_use = false;
            break;
        }
    }
    pthread_cond_signal(&conn_pool_cond);
    pthread_mutex_unlock(&conn_pool_mutex);
}

static void close_connection_pool() {
    if (connection_pool) {
        for (int i = 0; i < connections_in_pool; i++) {
            mysql_close(connection_pool[i].conn);
        }
        free(connection_pool);
        connection_pool = NULL;
        connections_in_pool = 0;
    }
}

static int create_connection_pool(char *password) {
    close_connection_pool();
    pthread_mutex_lock(&config_mutex);
    int pool_size = config.connection_pool_size;
    pthread_mutex_unlock(&config_mutex);

    connection_pool = (db_connection_t*)malloc(sizeof(db_connection_t) * pool_size);
    if (!connection_pool) {
        log_msg(LOG_ERROR_LVL, "Failed to allocate memory for connection pool.");
        return -1;
    }
    
    connections_in_pool = 0;
    for (int i = 0; i < pool_size; i++) {
        MYSQL *conn = mysql_init(NULL);
        if (!conn) {
            log_msg(LOG_ERROR_LVL, "Failed to initialize MySQL connection for pool.");
            close_connection_pool();
            return -1;
        }
        pthread_mutex_lock(&config_mutex);
        if (!mysql_real_connect(conn, config.db_host, config.db_user, password, NULL, config.db_port, NULL, 0)) {
            log_msg(LOG_ERROR_LVL, "DB connect failed for pool: %s", mysql_error(conn));
            mysql_close(conn);
            pthread_mutex_unlock(&config_mutex);
            close_connection_pool();
            return -1;
        }
        pthread_mutex_unlock(&config_mutex);
        connection_pool[i].conn = conn;
        connection_pool[i].is_in_use = false;
        connections_in_pool++;
    }
    log_msg(LOG_INFO_LVL, "Successfully created a connection pool of size %d.", connections_in_pool);
    return 0;
}


// -----------------------------
// Monitor loop
// -----------------------------
typedef struct {
    UserLimit *ul;
} ThreadArgs;

void check_user_task(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    
    MYSQL *conn = NULL;
    pthread_mutex_lock(&config_mutex);
    if (config.use_connection_pool) {
        pthread_mutex_unlock(&config_mutex);
        conn = get_conn_from_pool();
    } else {
        char password[128];
        secure_zero(password, sizeof(password));
        if (get_db_password(config.db_pass_file, password, sizeof(password)) != 0) {
            free(args);
            pthread_mutex_unlock(&config_mutex);
            return;
        }
        conn = mysql_init(NULL);
        if (!conn) {
            log_msg(LOG_ERROR_LVL, "Failed to initialize MySQL connection in thread.");
            free(args);
            pthread_mutex_unlock(&config_mutex);
            return;
        }
        
        if (mysql_real_connect(conn, config.db_host, config.db_user, password, NULL, config.db_port, NULL, 0) == NULL) {
            log_msg(LOG_ERROR_LVL, "Thread DB connect failed for user %s: %s", args->ul->user, mysql_error(conn));
            mysql_close(conn);
            free(args);
            pthread_mutex_unlock(&config_mutex);
            return;
        }
        secure_zero(password, sizeof(password));
        pthread_mutex_unlock(&config_mutex);
    }
    
    DBType dbt = detect_db_version(conn);
    long long usage = get_user_usage(conn, args->ul->user);
    if (usage < 0) {
        if (config.use_connection_pool) {
            return_conn_to_pool(conn);
        } else {
            mysql_close(conn);
        }
        free(args);
        return;
    }
    
    args->ul->last_usage = usage;
    log_msg(LOG_DEBUG_LVL,"User %s usage: %lld bytes", args->ul->user, usage);

    pthread_mutex_lock(&config_mutex);
    if (usage > args->ul->hard_limit) {
        args->ul->hard_count++;
        args->ul->status = 2;
        if (args->ul->hard_count >= config.threshold_trigger) {
            log_msg(LOG_ERROR_LVL, "User %s exceeded HARD limit: %lld > %lld", args->ul->user, usage, args->ul->hard_limit);
            if (!dry_run) {
                lock_user_account(conn, args->ul->user, dbt);
                if (config.kill_on_hard_limit) kill_user_sessions(conn, args->ul->user);
            } else {
                log_msg(LOG_WARN_LVL, "DRY-RUN: Would have locked and killed sessions for user %s.", args->ul->user);
            }
            args->ul->hard_count = 0;
        }
    } else if (usage > args->ul->soft_limit) {
        args->ul->soft_count++;
        args->ul->status = 1;
        if (args->ul->soft_count >= config.threshold_trigger) {
            log_msg(LOG_WARN_LVL, "User %s exceeded SOFT limit: %lld > %lld", args->ul->user, usage, args->ul->soft_limit);
            args->ul->soft_count = 0;
        }
    } else {
        args->ul->status = 0;
        args->ul->soft_count = 0;
        args->ul->hard_count = 0;
    }
    pthread_mutex_unlock(&config_mutex);
    
    if (config.use_connection_pool) {
        return_conn_to_pool(conn);
    } else {
        mysql_close(conn);
    }
    
    free(args);
}

static void monitor_loop() {
    char password[128];
    secure_zero(password, sizeof(password));
    
    while(keep_running) {
        if(reload_config_flag) {
            pthread_mutex_lock(&config_mutex);
            if(load_config()==0) {
                 log_msg(LOG_INFO_LVL, "Configuration reloaded successfully.");
                 if (config.use_connection_pool) {
                     get_db_password(config.db_pass_file, password, sizeof(password));
                     create_connection_pool(password);
                     secure_zero(password, sizeof(password));
                 } else {
                     close_connection_pool();
                 }
            } else {
                 log_msg(LOG_ERROR_LVL, "Failed to reload config, keeping old config.");
            }
            pthread_mutex_unlock(&config_mutex);
            reload_config_flag = 0;
        }

        pthread_mutex_lock(&config_mutex);
        if (config.use_threads) {
            if (!pool) {
                pool = thread_pool_create(config.max_threads, user_limit_count + 10);
                if (!pool) {
                    log_msg(LOG_ERROR_LVL, "Failed to create thread pool. Falling back to single-threaded mode.");
                    config.use_threads = false;
                } else if (config.use_connection_pool) {
                    if (get_db_password(config.db_pass_file, password, sizeof(password)) != 0) {
                         pthread_mutex_unlock(&config_mutex);
                         goto next_loop;
                    }
                    create_connection_pool(password);
                    secure_zero(password, sizeof(password));
                }
            }
            
            for (int i = 0; i < user_limit_count; i++) {
                ThreadArgs *args = (ThreadArgs *)malloc(sizeof(ThreadArgs));
                if (!args) {
                    log_msg(LOG_ERROR_LVL, "Failed to allocate memory for thread arguments.");
                    break;
                }
                args->ul = &user_limits[i];
                thread_pool_add_task(pool, check_user_task, args);
            }
        } else {
            // Single-threaded loop
            if (get_db_password(config.db_pass_file, password, sizeof(password)) != 0) {
                pthread_mutex_unlock(&config_mutex);
                goto next_loop;
            }
            MYSQL *conn=mysql_init(NULL);
            if(!conn) { 
                log_msg(LOG_ERROR_LVL, "Failed to initialize MySQL connection: %s", mysql_error(conn));
                pthread_mutex_unlock(&config_mutex);
                goto next_loop;
            }

            if(!mysql_real_connect(conn,config.db_host,config.db_user,password,NULL,config.db_port,NULL,0)) {
                log_msg(LOG_ERROR_LVL,"DB connect failed: %s",mysql_error(conn));
                mysql_close(conn); 
                pthread_mutex_unlock(&config_mutex);
                goto next_loop;
            }
            secure_zero(password, sizeof(password));
            
            DBType dbt=detect_db_version(conn);

            for(int i=0;i<user_limit_count;i++) {
                UserLimit *ul=&user_limits[i];
                long long usage=get_user_usage(conn,ul->user);
                if(usage<0) continue;
                ul->last_usage=usage;
                log_msg(LOG_DEBUG_LVL,"User %s usage: %lld bytes", ul->user, usage);
                
                if(usage>ul->hard_limit) {
                    ul->hard_count++;
                    ul->status=2;
                    if(ul->hard_count>=config.threshold_trigger) {
                        log_msg(LOG_ERROR_LVL,"User %s exceeded HARD limit: %lld > %lld", ul->user,usage,ul->hard_limit);
                        if (!dry_run) {
                            lock_user_account(conn,ul->user,dbt);
                            if(config.kill_on_hard_limit) kill_user_sessions(conn,ul->user);
                        } else {
                            log_msg(LOG_WARN_LVL, "DRY-RUN: Would have locked and killed sessions for user %s.", ul->user);
                        }
                        ul->hard_count=0;
                    }
                } else if(usage>ul->soft_limit) {
                    ul->soft_count++;
                    ul->status=1;
                    if(ul->soft_count>=config.threshold_trigger) {
                        log_msg(LOG_WARN_LVL,"User %s exceeded SOFT limit: %lld > %lld", ul->user,usage,ul->soft_limit);
                        ul->soft_count=0;
                    }
                } else {
                    ul->status=0;
                    ul->soft_count=0;
                    ul->hard_count=0;
                }
            }
            mysql_close(conn);
        }
        pthread_mutex_unlock(&config_mutex);

        write_prometheus_metrics(config.db_type, config.db_host);
        
next_loop:
        secure_zero(password, sizeof(password));
        sleep(config.check_interval > 0 ? config.check_interval : 10);
    }
}

// -----------------------------
// Daemonize
// -----------------------------
static int drop_privileges() {
    if (strlen(config.daemon_group) > 0) {
        struct group *grp = getgrnam(config.daemon_group);
        if (grp) {
            if (setgid(grp->gr_gid) != 0) {
                log_msg(LOG_ERROR_LVL, "Failed to setgid to %s: %s", config.daemon_group, strerror(errno));
                return -1;
            }
        } else {
            log_msg(LOG_ERROR_LVL, "Group '%s' not found.", config.daemon_group);
            return -1;
        }
    }
    
    if (strlen(config.daemon_user) > 0) {
        struct passwd *pwd = getpwnam(config.daemon_user);
        if (pwd) {
            if (setuid(pwd->pw_uid) != 0) {
                log_msg(LOG_ERROR_LVL, "Failed to setuid to %s: %s", config.daemon_user, strerror(errno));
                return -1;
            }
        } else {
            log_msg(LOG_ERROR_LVL, "User '%s' not found.", config.daemon_user);
            return -1;
        }
    }
    return 0;
}

static void daemonize() {
    pid_t pid=fork();
    if(pid<0) {
        log_msg(LOG_ERROR_LVL, "Fork failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if(pid>0) exit(EXIT_SUCCESS);

    umask(0);

    if(setsid()<0) {
        log_msg(LOG_ERROR_LVL, "setsid failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid < 0) {
        log_msg(LOG_ERROR_LVL, "Second fork failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if(chdir("/")<0) {
        log_msg(LOG_ERROR_LVL, "chdir failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    #ifdef __FreeBSD__
    const char *pid_file_path = "/var/run/storage_guard.pid";
    pfh = pidfile_open(pid_file_path, 0600, &pid);
    if (pfh == NULL) {
        if (errno == EEXIST) {
            log_msg(LOG_ERROR_LVL, "Daemon already running. PID: %d", pid);
            exit(EXIT_FAILURE);
        }
        log_msg(LOG_ERROR_LVL, "Could not open PID file %s: %s", pid_file_path, strerror(errno));
        exit(EXIT_FAILURE);
    }
    pidfile_write(pfh);
    #else
    const char *pid_file_path = "/var/run/storage_guard.pid";
    pid_t current_pid = getpid();
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", current_pid);

    pid_fd = open(pid_file_path, O_RDWR | O_CREAT, 0600);
    if (pid_fd < 0) {
        log_msg(LOG_ERROR_LVL, "Could not open PID file %s: %s", pid_file_path, strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (flock(pid_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            log_msg(LOG_ERROR_LVL, "Daemon already running.");
        } else {
            log_msg(LOG_ERROR_LVL, "Could not lock PID file %s: %s", pid_file_path, strerror(errno));
        }
        close(pid_fd);
        exit(EXIT_FAILURE);
    }
    if (ftruncate(pid_fd, 0) != 0 || write(pid_fd, pid_str, strlen(pid_str)) != strlen(pid_str)) {
        log_msg(LOG_ERROR_LVL, "Could not write to PID file %s: %s", pid_file_path, strerror(errno));
        close(pid_fd);
        exit(EXIT_FAILURE);
    }
    #endif
    log_msg(LOG_INFO_LVL, "Daemon started with PID: %d", getpid());
    
    if(drop_privileges() != 0) {
        exit(EXIT_FAILURE);
    }
}

static void cleanup_and_exit() {
    log_msg(LOG_INFO_LVL,"storage_guard stopped");
    
    if (pool) {
        thread_pool_destroy(pool);
    }
    
    close_connection_pool();
    
    #ifdef __FreeBSD__
    if(pfh) {
        pidfile_remove(pfh);
    }
    #else
    if(pid_fd != -1) {
        close(pid_fd);
        remove("/var/run/storage_guard.pid");
    }
    #endif

    if (log_fp) {
        fclose(log_fp);
    } else {
        closelog();
    }
    
    pthread_mutex_destroy(&config_mutex);
    pthread_mutex_destroy(&log_mutex);
}

// -----------------------------
// Main
// -----------------------------
int main(int argc,char *argv[]) {
    int foreground_mode = 0;
    dry_run = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--foreground") == 0) {
            foreground_mode = 1;
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run = 1;
        }
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    openlog("storage_guard",LOG_PID|LOG_CONS,LOG_DAEMON);

    if(load_config()!=0) {
        log_msg(LOG_ERROR_LVL, "Initial configuration load failed. Exiting.");
        closelog();
        return EXIT_FAILURE;
    }

    if (dry_run) {
        log_msg(LOG_WARN_LVL, "Running in DRY-RUN mode. No changes will be made to the database.");
    }
    
    if (!foreground_mode) {
        daemonize();
    } else {
        log_msg(LOG_INFO_LVL, "Running in foreground mode.");
    }

    pthread_mutex_lock(&config_mutex);
    if (config.use_connection_pool) {
        char password[128];
        if (get_db_password(config.db_pass_file, password, sizeof(password)) == 0) {
            create_connection_pool(password);
            secure_zero(password, sizeof(password));
        }
    }
    pthread_mutex_unlock(&config_mutex);
    
    monitor_loop();

    cleanup_and_exit();
    return EXIT_SUCCESS;
}
