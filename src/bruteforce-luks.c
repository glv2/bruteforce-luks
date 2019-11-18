/*
Bruteforce a LUKS volume.

Copyright 2014-2019 Guillaume LE VAILLANT

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include <errno.h>
#include <libcryptsetup.h>
#include <locale.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include "version.h"


#ifndef CRYPT_LUKS
/* Passing NULL to crypt_load will default to LUKS1 on older libcryptsetup versions. */
#define CRYPT_LUKS NULL
#endif

#define LAST_PASS_MAX_SHOWN_LENGTH 256

unsigned char *default_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char *path = NULL, *dictionary_file = NULL, *state_file = NULL;
wchar_t *charset = NULL, *prefix = NULL, *suffix = NULL;
unsigned int charset_len, min_len = 1, max_len = 8, prefix_len = 0, suffix_len = 0;
FILE *dictionary = NULL;
pthread_mutex_t found_password_lock, get_password_lock;
char stop = 0, found_password = 0;
unsigned int nb_threads = 1;
unsigned char last_pass[LAST_PASS_MAX_SHOWN_LENGTH];
time_t start_time;
unsigned int status_interval = 0;
struct itimerval progress_timer, state_timer;
struct decryption_func_locals
{
  unsigned long long int counter;
} *thread_locals;
unsigned int len = 0;
unsigned int *tab = NULL;


/*
 * Statistics
 */

void handle_signal(int signo)
{
  unsigned long long int total_ops = 0;
  unsigned int i, l;
  unsigned int l_full = max_len - suffix_len - prefix_len;
  unsigned int l_skip = min_len - suffix_len - prefix_len;
  double space = 0;
  double pw_per_seconds;
  time_t current_time, eta_time;
  struct tm *time_info;
  char datestr[256];

  current_time = time(NULL);

  for(i = 0; i < nb_threads; i++)
    total_ops += thread_locals[i].counter;

  pw_per_seconds = (double) total_ops / (current_time - start_time);

  if(dictionary == NULL)
  {
    for(l = l_skip; l <= l_full; l++)
      space += pow(charset_len, l);

    eta_time = ((space - total_ops) / pw_per_seconds) + start_time;
  }

  if(dictionary == NULL)
    fprintf(stderr, "Tried / Total passwords: %llu / %g\n", total_ops, space);
  else
    fprintf(stderr, "Tried passwords: %llu\n", total_ops);
  fprintf(stderr, "Tried passwords per second: %lf\n", pw_per_seconds);
  fprintf(stderr, "Last tried password: %s\n", last_pass);
  if(dictionary == NULL)
  {
    fprintf(stderr, "Total space searched: %lf%%\n", (total_ops / space) * 100);
    if(eta_time > 6307000000)
    {
      fprintf(stderr, "ETA: more than 200 years :(\n");
    }
    else
    {
      time_info = localtime(&eta_time);
      if(time_info && (strftime(datestr, 256, "%c", time_info) > 0))
        fprintf(stderr, "ETA: %s\n", datestr);
      else
        fprintf(stderr, "ETA: %ld s\n", eta_time - start_time);
    }
  }
  fprintf(stderr, "\n");
}


/*
 * Log function
 */

void logger(int level, const char *msg, void *usrptr)
{
  int *ret = (int *) usrptr;

  if((level == CRYPT_LOG_ERROR) && (*ret < -1))
    fprintf(stderr, "Error: %s\n", msg);
}


/*
 * Decryption
 */

int generate_next_password(unsigned char **pwd, unsigned int *pwd_len)
{
  wchar_t *password;
  unsigned int password_len, i;

  pthread_mutex_lock(&get_password_lock);

  if(len == 0)
    len = min_len - prefix_len - suffix_len;
  if(len > max_len - prefix_len - suffix_len)
  {
    pthread_mutex_unlock(&get_password_lock);
    return(0);
  }

  /* Initialize index table */
  if(tab == NULL)
  {
    tab = (unsigned int *) calloc(len + 1, sizeof(unsigned int));
    if(tab == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      pthread_mutex_unlock(&get_password_lock);
      exit(EXIT_FAILURE);
    }
  }

  /* Make password */
  password_len = prefix_len + len + suffix_len;
  password = (wchar_t *) calloc(password_len + 1, sizeof(wchar_t));
  if((password == NULL))
  {
    fprintf(stderr, "Error: memory allocation failed.\n\n");
    pthread_mutex_unlock(&get_password_lock);
    exit(EXIT_FAILURE);
  }
  wcsncpy(password, prefix, prefix_len);
  for(i = 0; i < len; i++)
    password[prefix_len + i] = charset[tab[len - 1 - i]];
  wcsncpy(password + prefix_len + len, suffix, suffix_len);
  password[password_len] = '\0';
  *pwd_len = wcstombs(NULL, password, 0);
  *pwd = (unsigned char *) malloc(*pwd_len + 1);
  if(*pwd == NULL)
  {
    fprintf(stderr, "Error: memory allocation failed.\n\n");
    pthread_mutex_unlock(&get_password_lock);
    exit(EXIT_FAILURE);
  }
  wcstombs(*pwd, password, *pwd_len + 1);
  free(password);
  snprintf(last_pass, LAST_PASS_MAX_SHOWN_LENGTH, "%s", *pwd);

  /* Prepare next password */
  tab[0]++;
  if(tab[0] == charset_len)
    tab[0] = 0;
  i = 0;
  while((i < len) && (tab[i] == 0))
  {
    i++;
    tab[i]++;
    if(tab[i] == charset_len)
      tab[i] = 0;
  }
  if(tab[len] != 0)
  {
    free(tab);
    tab = NULL;
    len++;
  }

  pthread_mutex_unlock(&get_password_lock);

  return(1);
}

int read_dictionary_line(unsigned char **line, unsigned int *n)
{
  unsigned int size;
  int ret;

  *n = 0;
  size = 32;
  *line = (unsigned char *) malloc(size);
  if(*line == NULL)
  {
    fprintf(stderr, "Error: memory allocation failed.\n\n");
    exit(EXIT_FAILURE);
  }

  pthread_mutex_lock(&get_password_lock);
  while(1)
  {
    ret = fgetc(dictionary);
    if(ret == EOF)
    {
      if(*n == 0)
      {
        free(*line);
        *line = NULL;
        pthread_mutex_unlock(&get_password_lock);
        return(0);
      }
      else
        break;
    }

    if((ret == '\r') || (ret == '\n'))
    {
      if(*n == 0)
        continue;
      else
        break;
    }

    (*line)[*n] = (unsigned char) ret;
    (*n)++;

    if(*n == size)
    {
      size *= 2;
      *line = (unsigned char *) realloc(*line, size);
      if(*line == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        pthread_mutex_unlock(&get_password_lock);
        exit(EXIT_FAILURE);
      }
    }
  }

  (*line)[*n] = '\0';
  snprintf(last_pass, LAST_PASS_MAX_SHOWN_LENGTH, "%s", *line);

  pthread_mutex_unlock(&get_password_lock);

  return(1);
}

void * decryption_func(void *arg)
{
  struct decryption_func_locals *dfargs;
  unsigned char *pwd;
  unsigned int pwd_len;
  int ret;
  struct crypt_device *cd;

  dfargs = (struct decryption_func_locals *) arg;

  /* Load the LUKS volume header */
  crypt_init(&cd, path);
  crypt_load(cd, CRYPT_LUKS, NULL);
  crypt_set_log_callback(cd, &logger, &ret);

  do
  {
    if(dictionary == NULL)
      ret = generate_next_password(&pwd, &pwd_len);
    else
      ret = read_dictionary_line(&pwd, &pwd_len);
    if(ret == 0)
      break;

    /* Decrypt the LUKS volume with the password */
    ret = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, pwd, pwd_len, CRYPT_ACTIVATE_READONLY);
    if(ret >= 0)
    {
      /* We have a positive result */
      handle_signal(SIGUSR1); /* Print some stats */
      pthread_mutex_lock(&found_password_lock);
      found_password = 1;
      printf("Password found: %s\n", pwd);
      stop = 1;
      pthread_mutex_unlock(&found_password_lock);
    }
    dfargs->counter++;

    free(pwd);
  }
  while(stop == 0);

  crypt_free(cd);

  pthread_exit(NULL);
}


/*
 * Save/restore state
 */

void save_state(int signo)
{
  unsigned int i;
  unsigned long long int total_ops = 0;
  unsigned long long int run_time = time(NULL) - start_time;
  FILE *state = fopen(state_file, "w+");

  if(state == NULL)
  {
    fprintf(stderr, "Error: can't open state file.\n\n");
    return;
  }

  for(i = 0; i < nb_threads; i++)
    total_ops += thread_locals[i].counter;

  if(dictionary == NULL)
  {
    fprintf(state, "luks %s\n", path);
    fprintf(state, "time %llu\n", run_time);
    fprintf(state, "bruteforce %u %u\n", min_len, max_len);
    fprintf(state, "charset %ls\n", charset);
    fprintf(state, "prefix %ls\n", prefix);
    fprintf(state, "suffix %ls\n", suffix);
    fprintf(state, "%llu\n", total_ops);
    fprintf(state, "%u\n", len);
    for(i = 0; i < len; i++)
      fprintf(state, "%u ", tab[i]);
    fprintf(state, "\n");
  }
  else
  {
    fprintf(state, "luks %s\n", path);
    fprintf(state, "time %llu\n", run_time);
    fprintf(state, "dictionary %s\n", dictionary_file);
    fprintf(state, "%llu\n", total_ops);
  }

  fclose(state);
}

void restore_state()
{
  unsigned int i, n;
  unsigned long long int total_ops = 0;
  unsigned long long int run_time;
  unsigned char *line;
  FILE *state = fopen(state_file, "r");

  if(state == NULL)
  {
    fprintf(stderr, "Warning: can't open state file, state not restored, a new file will be created.\n\n");
    return;
  }

  fprintf(stderr, "Warning: restoring state, ignoring options -b, -e, -f, -l, -m and -s.\n\n");

  if(dictionary != NULL)
    fclose(dictionary);

  if((fscanf(state, "luks %ms\n", &line) != 1)
     || (fscanf(state, "time %llu\n", &run_time) != 1))
  {
    fprintf(stderr, "Error: parsing the state file failed.\n\n");
    exit(EXIT_FAILURE);
  }
  free(line);
  start_time = time(NULL) - run_time;

  if(fscanf(state, "bruteforce %u %u\n", &min_len, &max_len) == 2)
  {
    dictionary = state;

    if((read_dictionary_line(&line, &n) == 0) || (n < 8))
    {
      fprintf(stderr, "Error: parsing the state file failed.\n\n");
      exit(EXIT_FAILURE);
    }
    charset_len = mbstowcs(NULL, line + 8, 0);
    if(charset_len == 0)
    {
      fprintf(stderr, "Error: charset must have at least one character.\n\n");
      exit(EXIT_FAILURE);
    }
    if(charset_len == (unsigned int) -1)
    {
      fprintf(stderr, "Error: invalid character in charset.\n\n");
      exit(EXIT_FAILURE);
    }
    charset = (wchar_t *) calloc(charset_len + 1, sizeof(wchar_t));
    if(charset == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
    mbstowcs(charset, line + 8, charset_len + 1);

    if((read_dictionary_line(&line, &n) == 0) || (n < 7))
    {
      fprintf(stderr, "Error: parsing the state file failed.\n\n");
      exit(EXIT_FAILURE);
    }
    prefix_len = mbstowcs(NULL, line + 7, 0);
    if(prefix_len == (unsigned int) -1)
    {
      fprintf(stderr, "Error: invalid character in prefix.\n\n");
      exit(EXIT_FAILURE);
    }
    prefix = (wchar_t *) calloc(prefix_len + 1, sizeof(wchar_t));
    if(prefix == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
    mbstowcs(prefix, line + 7, prefix_len + 1);

    if((read_dictionary_line(&line, &n) == 0) || (n < 7))
    {
      fprintf(stderr, "Error: parsing the state file failed.\n\n");
      exit(EXIT_FAILURE);
    }
    suffix_len = mbstowcs(NULL, line + 7, 0);
    if(suffix_len == (unsigned int) -1)
    {
      fprintf(stderr, "Error: invalid character in suffix.\n\n");
      exit(EXIT_FAILURE);
    }
    suffix = (wchar_t *) calloc(suffix_len + 1, sizeof(wchar_t));
    if(suffix == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
    mbstowcs(suffix, line + 7, suffix_len + 1);

    dictionary = NULL;

    if(fscanf(state, "%llu\n", &total_ops) != 1)
    {
      fprintf(stderr, "Error: parsing the state file failed.\n\n");
      exit(EXIT_FAILURE);
    }
    thread_locals[0].counter = total_ops;

    if(fscanf(state, "%u\n", &len) != 1)
    {
      fprintf(stderr, "Error: parsing the state file failed.\n\n");
      exit(EXIT_FAILURE);
    }

    tab = (unsigned int *) calloc(len + 1, sizeof(unsigned int));
    if(tab == NULL)
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
    for(i = 0; i < len; i++)
      if(fscanf(state, "%u ", &tab[i]) != 1)
      {
        fprintf(stderr, "Error: parsing the state file failed.\n\n");
        exit(EXIT_FAILURE);
      }
  }
  else if(fscanf(state, "dictionary %ms\n", &dictionary_file) == 1)
  {
    if(fscanf(state, "%llu\n", &total_ops) != 1)
    {
      fprintf(stderr, "Error: parsing the state file failed.\n\n");
      exit(EXIT_FAILURE);
    }
    thread_locals[0].counter = total_ops;

    dictionary = fopen(dictionary_file, "r");
    if(dictionary == NULL)
    {
      fprintf(stderr, "Error: can't open dictionary file.\n\n");
      exit(EXIT_FAILURE);
    }

    for(i = 0; i < total_ops; i++)
      read_dictionary_line(&line, &n);
  }
  else
  {
    fprintf(stderr, "Error: parsing the state file failed.\n\n");
    exit(EXIT_FAILURE);
  }

  fclose(state);
}


/*
 * Check path
 */

int check_path(char *path)
{
  struct crypt_device *cd;
  int ret;

  ret = crypt_init(&cd, path);
  if(ret < 0)
    return(0);

  ret = crypt_load(cd, CRYPT_LUKS, NULL);
  if(ret < 0)
  {
    crypt_free(cd);
    return(0);
  }

  crypt_free(cd);
  return(1);
}


/*
 * Main
 */

void usage(char *progname)
{
  fprintf(stderr, "\nbruteforce-luks %s\n\n", VERSION_NUMBER);
  fprintf(stderr, "Usage: %s [options] <path to LUKS volume>\n\n", progname);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -b <string>  Beginning of the password.\n");
  fprintf(stderr, "                 default: \"\"\n");
  fprintf(stderr, "  -e <string>  End of the password.\n");
  fprintf(stderr, "                 default: \"\"\n");
  fprintf(stderr, "  -f <file>    Read the passwords from a file instead of generating them.\n");
  fprintf(stderr, "  -h           Show help and quit.\n");
  fprintf(stderr, "  -l <length>  Minimum password length (beginning and end included).\n");
  fprintf(stderr, "                 default: 1\n");
  fprintf(stderr, "  -m <length>  Maximum password length (beginning and end included).\n");
  fprintf(stderr, "                 default: 8\n");
  fprintf(stderr, "  -s <string>  Password character set.\n");
  fprintf(stderr, "                 default: \"0123456789ABCDEFGHIJKLMNOPQRSTU\n");
  fprintf(stderr, "                           VWXYZabcdefghijklmnopqrstuvwxyz\"\n");
  fprintf(stderr, "  -t <n>       Number of threads to use.\n");
  fprintf(stderr, "                 default: 1\n");
  fprintf(stderr, "  -v <n>       Print progress info every n seconds.\n");
  fprintf(stderr, "  -w <file>    Restore the state of a previous session if the file exists,\n");
  fprintf(stderr, "               then write the state to the file regularly (~ every minute).\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Sending a USR1 signal to a running bruteforce-luks process\n");
  fprintf(stderr, "makes it print progress info to standard error and continue.\n");
  fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
  pthread_t *decryption_threads;
  int i, ret, c;

  setlocale(LC_ALL, "");

  /* Get options and parameters. */
  opterr = 0;
  while((c = getopt(argc, argv, "b:e:f:hl:m:s:t:v:w:")) != -1)
    switch(c)
    {
    case 'b':
      prefix_len = mbstowcs(NULL, optarg, 0);
      if(prefix_len == (unsigned int) -1)
      {
        fprintf(stderr, "Error: invalid character in prefix.\n\n");
        exit(EXIT_FAILURE);
      }
      prefix = (wchar_t *) calloc(prefix_len + 1, sizeof(wchar_t));
      if(prefix == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        exit(EXIT_FAILURE);
      }
      mbstowcs(prefix, optarg, prefix_len + 1);
      break;

    case 'e':
      suffix_len = mbstowcs(NULL, optarg, 0);
      if(suffix_len == (unsigned int) -1)
      {
        fprintf(stderr, "Error: invalid character in suffix.\n\n");
        exit(EXIT_FAILURE);
      }
      suffix = (wchar_t *) calloc(suffix_len + 1, sizeof(wchar_t));
      if(suffix == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        exit(EXIT_FAILURE);
      }
      mbstowcs(suffix, optarg, suffix_len + 1);
      break;

    case 'f':
      dictionary_file = optarg;
      dictionary = fopen(dictionary_file, "r");
      if(dictionary == NULL)
      {
        fprintf(stderr, "Error: can't open dictionary file.\n\n");
        exit(EXIT_FAILURE);
      }
      break;

    case 'h':
      usage(argv[0]);
      exit(EXIT_FAILURE);
      break;

    case 'l':
      min_len = (unsigned int) atoi(optarg);
      break;

    case 'm':
      max_len = (unsigned int) atoi(optarg);
      break;

    case 's':
      charset_len = mbstowcs(NULL, optarg, 0);
      if(charset_len == 0)
      {
        fprintf(stderr, "Error: charset must have at least one character.\n\n");
        exit(EXIT_FAILURE);
      }
      if(charset_len == (unsigned int) -1)
      {
        fprintf(stderr, "Error: invalid character in charset.\n\n");
        exit(EXIT_FAILURE);
      }
      charset = (wchar_t *) calloc(charset_len + 1, sizeof(wchar_t));
      if(charset == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        exit(EXIT_FAILURE);
      }
      mbstowcs(charset, optarg, charset_len + 1);
      break;

    case 't':
      nb_threads = (unsigned int) atoi(optarg);
      if(nb_threads == 0)
        nb_threads = 1;
      break;

    case 'v':
      status_interval = (unsigned int) atoi(optarg);
      break;

    case 'w':
      state_file = optarg;
      break;

    default:
      usage(argv[0]);
      switch(optopt)
      {
      case 'b':
      case 'e':
      case 'f':
      case 'l':
      case 'm':
      case 's':
      case 't':
      case 'v':
      case 'w':
        fprintf(stderr, "Error: missing argument for option: '-%c'.\n\n", optopt);
        break;

      default:
        fprintf(stderr, "Error: unknown option: '%c'.\n\n", optopt);
        break;
      }
      exit(EXIT_FAILURE);
      break;
    }

  if(optind >= argc)
  {
    usage(argv[0]);
    fprintf(stderr, "Error: missing path to LUKS volume.\n\n");
    exit(EXIT_FAILURE);
  }

  path = argv[optind];

  /* Check variables */
  if(dictionary != NULL)
  {
    fprintf(stderr, "Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.\n\n");
  }
  else
  {
    if(prefix == NULL)
    {
      prefix_len = mbstowcs(NULL, "", 0);
      prefix = (wchar_t *) calloc(prefix_len + 1, sizeof(wchar_t));
      if(prefix == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        exit(EXIT_FAILURE);
      }
      mbstowcs(prefix, "", prefix_len + 1);
    }
    if(suffix == NULL)
    {
      suffix_len = mbstowcs(NULL, "", 0);
      suffix = (wchar_t *) calloc(suffix_len + 1, sizeof(wchar_t));
      if(suffix == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        exit(EXIT_FAILURE);
      }
      mbstowcs(suffix, "", suffix_len + 1);
    }
    if(charset == NULL)
    {
      charset_len = mbstowcs(NULL, default_charset, 0);
      charset = (wchar_t *) calloc(charset_len + 1, sizeof(wchar_t));
      if(charset == NULL)
      {
        fprintf(stderr, "Error: memory allocation failed.\n\n");
        exit(EXIT_FAILURE);
      }
      mbstowcs(charset, default_charset, charset_len + 1);
    }
    if(min_len < prefix_len + suffix_len + 1)
    {
      fprintf(stderr, "Warning: minimum length (%u) smaller than the length of specified password characters (%u). Setting minimum length to %u.\n\n", min_len, prefix_len + suffix_len, prefix_len + suffix_len + 1);
      min_len = prefix_len + suffix_len + 1;
    }
    if(max_len < min_len)
    {
      fprintf(stderr, "Warning: maximum length (%u) smaller than minimum length (%u). Setting maximum length to %u.\n\n", max_len, min_len, min_len);
      max_len = min_len;
    }
  }

  last_pass[0] = '\0';

  /* Check if path points to a LUKS volume */
  ret = check_path(path);
  if(ret == 0)
  {
    fprintf(stderr, "Error: %s is not a valid LUKS volume, or you don't have permission to access it.\n\n", path);
    exit(EXIT_FAILURE);
  }

  signal(SIGUSR1, handle_signal);
  if(status_interval > 0)
  {
    signal(SIGALRM, handle_signal);
    progress_timer.it_value.tv_sec = status_interval;
    progress_timer.it_value.tv_usec = 0;
    progress_timer.it_interval.tv_sec = status_interval;
    progress_timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &progress_timer, NULL);
  }

  pthread_mutex_init(&found_password_lock, NULL);
  pthread_mutex_init(&get_password_lock, NULL);

  decryption_threads = (pthread_t *) malloc(nb_threads * sizeof(pthread_t));
  thread_locals = (struct decryption_func_locals *) calloc(nb_threads, sizeof(struct decryption_func_locals));
  if((decryption_threads == NULL) || (thread_locals == NULL))
  {
    fprintf(stderr, "Error: memory allocation failed.\n\n");
    exit(EXIT_FAILURE);
  }

  start_time = time(NULL);

  if(state_file != NULL)
  {
    restore_state();

    signal(SIGVTALRM, save_state);
    state_timer.it_value.tv_sec = 60 * nb_threads;
    state_timer.it_value.tv_usec = 0;
    state_timer.it_interval.tv_sec = 60 * nb_threads;
    state_timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_VIRTUAL, &state_timer, NULL);
  }

  /* Start decryption threads. */
  for(i = 0; i < nb_threads; i++)
  {
    ret = pthread_create(&decryption_threads[i], NULL, &decryption_func, &thread_locals[i]);
    if(ret != 0)
    {
      perror("Error: decryption thread");
      exit(EXIT_FAILURE);
    }
  }

  for(i = 0; i < nb_threads; i++)
  {
    pthread_join(decryption_threads[i], NULL);
  }
  if(found_password == 0)
  {
    handle_signal(SIGUSR1); /* Print some stats */
    fprintf(stderr, "Password not found\n");
  }
  free(thread_locals);
  free(decryption_threads);
  pthread_mutex_destroy(&found_password_lock);
  pthread_mutex_destroy(&get_password_lock);

  exit(EXIT_SUCCESS);
}
