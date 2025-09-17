//
// Created by Junyeong on 2025. 9. 17..
//

#include "log.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

static FILE *log_file = NULL;

void init_logger(const char *filename) {
    log_file = fopen(filename, "a");
    if (log_file == NULL) {
        perror("Could not open log file");
    }
}

void file_log(const char *format, ...) {
    if (log_file == NULL) return;

    time_t now = time(NULL);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[%s] ", time_buf);

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);
}

void cleanup_logger() {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}