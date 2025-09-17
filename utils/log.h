//
// Created by Junyeong on 2025. 9. 17..
//

#ifndef LOG_H
#define LOG_H

void init_logger(const char *filename);
void file_log(const char *format, ...);
void cleanup_logger();

#endif //LOG_H
