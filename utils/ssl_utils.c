//
// Created by Junyeong on 2025. 9. 10..
//

#include "ssl_utils.h"

unsigned long hash_string(const char *str) {
    unsigned long hash = 202411340;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}