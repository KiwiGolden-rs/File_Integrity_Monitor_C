#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define MAX_PATH 256
#define HASH_SIZE 65
#define BASELINE_FILE "/var/lib/integrity_monitor/baseline.txt"
#define LOG_FILE "/var/log/integrity_monitor.log"

const char *files_to_monitor[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/etc/ssh/ssh_config"
};

const int file_count = sizeof(files_to_monitor) / sizeof(files_to_monitor[0]);

void sha256_hash_file(const char *path, char *output) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        snprintf(output, HASH_SIZE, "ERROR");
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        snprintf(output, HASH_SIZE, "ERROR");
        return;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char buffer[4096];
    unsigned int hash_len = 0;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) !=0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    for (int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = 0;
}

void write_log(const char *format, ...) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("Cannot open log file");
        return;
    }

    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strcspn(timestamp, "\n")] = 0;

    fprintf(log, "[%s]", timestamp);

    va_list args;
    va_start(args, format);
    vfprintf(log, format, args);
    va_end(args);

    fprintf(log, "\n");
    fclose(log);
}

void generate_baseline() {
    mkdir("/var/lib/integrity_monitor", 0700);
    FILE *baseline = fopen(BASELINE_FILE, "w");
    if (!baseline) {
        perror("Cannot write baseline");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < file_count; i++) {
        char hash[HASH_SIZE];
        sha256_hash_file(files_to_monitor[i], hash);
        fprintf(baseline, "%s %s\n", files_to_monitor[i], hash);
    }
    fclose(baseline);
    printf("Baseline created successfully.\n");
}

void check_integrity() {
    FILE *baseline = fopen(BASELINE_FILE, "r");
    if (!baseline) {
        fprintf(stderr, "Baseline not found. Run with --init to generate one.\n");
        exit(EXIT_FAILURE);
    }

    char path[MAX_PATH];
    char saved_hash[HASH_SIZE];
    int changes_detected = 0;

    while (fscanf(baseline, "%s %s", path, saved_hash) == 2) {
        char current_hash[HASH_SIZE];
        sha256_hash_file(path, current_hash);

        if (strcmp(current_hash, "ERROR") == 0) {
            char msg[MAX_PATH + 50];
            snprintf(msg, sizeof(msg), "WARNING: File missing or unreadable: %s", path);
            write_log(msg);
            changes_detected = 1;
            continue;
        }

        if (strcmp(current_hash, saved_hash) != 0) {
            char msg[MAX_PATH + 100];
            snprintf(msg, sizeof(msg), "ALERT: File modified: %s", path);
            write_log(msg);
            changes_detected = 1;
        }
    }

    if (!changes_detected) {
        write_log("No file integrity issues detected.\n");
    }

    fclose(baseline);
    printf("Integrity check completed. See log: %s\n", LOG_FILE);
}

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root.\n");
        return EXIT_FAILURE;
    }

    if (argc > 1 && strcmp(argv[1], "--init") == 0) {
        generate_baseline();
    } else {
        check_integrity();
    }

    return EXIT_SUCCESS;
}