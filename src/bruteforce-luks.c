/*
Bruteforce a LUKS volume.

Copyright 2014-2016 Guillaume LE VAILLANT

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
#include <unistd.h>
#include <wchar.h>

#include "version.h"


unsigned char *default_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char *path = NULL;
wchar_t *charset = NULL, *prefix = NULL, *suffix = NULL;
unsigned int charset_len, min_len = 1, max_len = 8, prefix_len = 0, suffix_len = 0;
FILE *dictionary = NULL;
pthread_mutex_t found_password_lock, dictionary_lock;
char stop = 0, found_password = 0;
unsigned int nb_threads = 1;
struct decryption_func_locals
{
  unsigned int index_start;
  unsigned int index_end;
  unsigned long long int counter;
} *thread_locals;


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

  if(dictionary == NULL)
    for(l = l_skip; l <= l_full; l++)
      space += pow(charset_len, l);

  for(i = 0; i < nb_threads; i++)
    total_ops += thread_locals[i].counter;

  fprintf(stderr, "Tried passwords: %llu\n", total_ops);
  if(dictionary == NULL)
    fprintf(stderr, "Total space searched: %lf%%\n", (total_ops / space) * 100);
}


/*
 * Decryption
 */

/* The decryption_func_bruteforce thread function tests all the passwords of the form:
 *   prefix + x + combination + suffix
 * where x is a character in the range charset[dfargs.index_start] -> charset[dfargs.index_end]. */
void * decryption_func_bruteforce(void *arg)
{
  struct decryption_func_locals *dfargs;
  wchar_t *password;
  unsigned char *pwd;
  unsigned int password_len, pwd_len, index_start, index_end, len, i, j, k;
  int ret;
  unsigned int *tab;
  struct crypt_device *cd;

  dfargs = (struct decryption_func_locals *) arg;
  index_start = dfargs->index_start;
  index_end = dfargs->index_end;

  /* Load the LUKS volume header */
  crypt_init(&cd, path);
  crypt_load(cd, CRYPT_LUKS1, NULL);

  /* For every possible length */
  for(len = min_len - prefix_len - 1 - suffix_len; len + 1 <= max_len - prefix_len - suffix_len; len++)
    {
      /* For every first character in the range we were given */
      for(k = index_start; k <= index_end; k++)
        {
          password_len = prefix_len + 1 + len + suffix_len;
          password = (wchar_t *) calloc(password_len + 1, sizeof(wchar_t));
          tab = (unsigned int *) calloc(len + 1, sizeof(unsigned int));
          if((password == NULL) || (tab == NULL))
            {
              fprintf(stderr, "Error: memory allocation failed.\n\n");
              exit(EXIT_FAILURE);
            }
          wcsncpy(password, prefix, prefix_len);
          password[prefix_len] = charset[k];
          wcsncpy(password + prefix_len + 1 + len, suffix, suffix_len);
          password[password_len] = '\0';

          for(i = 0; i <= len; i++)
            tab[i] = 0;

          /* Test all the combinations */
          while((tab[len] == 0) && (stop == 0))
            {
              for(i = 0; i < len; i++)
                password[prefix_len + 1 + i] = charset[tab[len - 1 - i]];
              pwd_len = wcstombs(NULL, password, 0);
              pwd = (unsigned char *) malloc(pwd_len + 1);
              if(pwd == NULL)
                {
                  fprintf(stderr, "Error: memory allocation failed.\n\n");
                  exit(EXIT_FAILURE);
                }
              wcstombs(pwd, password, pwd_len + 1);

              /* Decrypt the LUKS volume with the password */
              ret = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, pwd, pwd_len, CRYPT_ACTIVATE_READONLY);
              dfargs->counter++;
              if(ret >= 0)
                {
                  /* We have a positive result */
                  handle_signal(SIGUSR1); /* Print some stats */
                  pthread_mutex_lock(&found_password_lock);
                  found_password = 1;
                  printf("Password found: %ls\n", password);
                  stop = 1;
                  pthread_mutex_unlock(&found_password_lock);
                }
              else if(ret < -1)
                {
                  fprintf(stderr, "Error: access to the LUKS volume denied.\n\n");
                  stop = 1;
                }

              free(pwd);

              if(len == 0)
                break;
              tab[0]++;
              if(tab[0] == charset_len)
                tab[0] = 0;
              j = 0;
              while((j < len) && (tab[j] == 0))
                {
                  j++;
                  tab[j]++;
                  if(tab[j] == charset_len)
                    tab[j] = 0;
                }
            }
          free(tab);
          free(password);
        }
    }

  crypt_free(cd);

  pthread_exit(NULL);
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

  while(1)
    {
      pthread_mutex_lock(&dictionary_lock);
      ret = fgetc(dictionary);
      pthread_mutex_unlock(&dictionary_lock);

      if(ret == EOF)
        {
          if(*n == 0)
            {
              free(*line);
              *line = NULL;
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
              exit(EXIT_FAILURE);
            }
        }
    }

  (*line)[*n] = '\0';

  return(1);
}

void * decryption_func_dictionary(void *arg)
{
  struct decryption_func_locals *dfargs;
  unsigned char *pwd;
  unsigned int pwd_len;
  int ret;
  struct crypt_device *cd;

  dfargs = (struct decryption_func_locals *) arg;

  /* Load the LUKS volume header */
  crypt_init(&cd, path);
  crypt_load(cd, CRYPT_LUKS1, NULL);

  do
    {
      ret = read_dictionary_line(&pwd, &pwd_len);
      if(ret == 0)
        break;

      /* Decrypt the LUKS volume with the password */
      ret = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, pwd, pwd_len, CRYPT_ACTIVATE_READONLY);
      dfargs->counter++;
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
      else if(ret < -1)
        {
          fprintf(stderr, "Error: access to the LUKS volume denied.\n\n");
          stop = 1;
        }

      free(pwd);
    }
  while(stop == 0);

  crypt_free(cd);

  pthread_exit(NULL);
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

  ret = crypt_load(cd, CRYPT_LUKS1, NULL);
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
  while((c = getopt(argc, argv, "b:e:f:hl:m:s:t:")) != -1)
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
        dictionary = fopen(optarg, "r");
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
      if(nb_threads > charset_len)
        {
          fprintf(stderr, "Warning: number of threads (%u) bigger than character set length (%u). Only using %u threads.\n\n", nb_threads, charset_len, charset_len);
          nb_threads = charset_len;
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

  signal(SIGUSR1, handle_signal);

  /* Check if path points to a LUKS volume */
  ret = check_path(path);
  if(ret == 0)
    {
      fprintf(stderr, "Error: either %s is not a valid LUKS volume, or you don't have permission to access it.\n\n", path);
      exit(EXIT_FAILURE);
    }

  pthread_mutex_init(&found_password_lock, NULL);
  pthread_mutex_init(&dictionary_lock, NULL);

  /* Start decryption threads. */
  decryption_threads = (pthread_t *) malloc(nb_threads * sizeof(pthread_t));
  thread_locals = (struct decryption_func_locals *) calloc(nb_threads, sizeof(struct decryption_func_locals));
  if((decryption_threads == NULL) || (thread_locals == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < nb_threads; i++)
    {
      if(dictionary == NULL)
        {
          thread_locals[i].index_start = i * (charset_len / nb_threads);
          if(i == nb_threads - 1)
            thread_locals[i].index_end = charset_len - 1;
          else
            thread_locals[i].index_end = (i + 1) * (charset_len / nb_threads) - 1;
          ret = pthread_create(&decryption_threads[i], NULL, &decryption_func_bruteforce, &thread_locals[i]);
        }
      else
        {
          thread_locals[i].index_start = i;
          ret = pthread_create(&decryption_threads[i], NULL, &decryption_func_dictionary, &thread_locals[i]);
        }
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
  pthread_mutex_destroy(&dictionary_lock);

  exit(EXIT_SUCCESS);
}
