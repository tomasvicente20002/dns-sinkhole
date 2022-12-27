#include "mylib.h"

void red()
{
   printf("\033[1;31m");
}
void yellow()
{
   printf("\033[1;33m");
}
void green()
{
   printf("\033[1;32m");
}
void blue()
{
   printf("\033[1;34m");
}
void reset()
{
   printf("\033[0m");
}

void log_message(log_level level, char *message, ...)
{
   va_list args;

   char *level_str;
   char *color;
   switch (level)
   {
   case DEBUG:
   {
      level_str = "DEBUG";
      blue();
      break;
   }
   case INFO:
   {
      level_str = "INFO";
      green();
      break;
   }
   case WARNING:
   {
      level_str = "WARNING";
      yellow();
      break;
   }
   case ERROR:
   {
      level_str = "ERROR";
      red();
      break;
   }
   }

  time_t t = time(NULL);
  struct tm tm = *localtime(&t);
  printf("%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

   printf(" [%s] ", level_str);
   va_start(args, message);
   vprintf(message, args);
   va_end(args);
   reset();
   printf("\n");

   FILE *fp = fopen("log.txt", "a");
   if (fp == NULL)
   {
      va_start(args, message);
      fprintf(fp,"%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
      fprintf(fp," [%s] ", level_str);
      vfprintf(fp, message, args);
      fprintf(fp,"\n");
      va_end(args);
      exit(1);
   }


   fclose(fp);
}


