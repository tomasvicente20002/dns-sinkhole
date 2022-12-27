#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
typedef int BOOL;
#define FALSE 0
#define TRUE 1



typedef enum {
  DEBUG,
  INFO,
  WARNING,
  ERROR
} log_level;

void log_message(log_level level, char* message,...);