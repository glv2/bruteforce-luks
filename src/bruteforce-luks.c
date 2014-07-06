/*
Bruteforce a LUKS volume.

Copyright 2014 Guillaume LE VAILLANT

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

#include <errno.h>
#include <libcryptsetup.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "version.h"


unsigned char *default_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
unsigned char *charset = NULL, *prefix = NULL, *suffix = NULL, *path = NULL;
unsigned int charset_len = 62, min_len = 1, max_len = 8, prefix_len = 0, suffix_len = 0;
pthread_mutex_t found_password_lock;
char stop = 0, only_one_password = 0;


/*
 * Decryption
 */

/* The decryption_func thread function tests all the passwords of the form:
 *   prefix + x + combination + suffix
 * where x is a character in the range charset[arg[0]] -> charset[arg[1]]. */
void * decryption_func(void *arg)
{
  unsigned char *password, device_name[64];
  unsigned int password_len, index_start, index_end, len, i, j, k;
  int ret;
  unsigned int *tab;
  struct crypt_device *cd;

  index_start = ((unsigned int *) arg)[0];
  index_end = ((unsigned int *) arg)[1];
  snprintf(device_name, sizeof(device_name), "luks_%u", index_start);

  /* For every possible length */
  for(len = min_len - prefix_len - 1 - suffix_len; len + 1 <= max_len - prefix_len - suffix_len; len++)
    {
      /* For every first character in the range we were given */
      for(k = index_start; k <= index_end; k++)
        {
          password_len = prefix_len + 1 + len + suffix_len;
          password = (unsigned char *) malloc(password_len + 1);
          tab = (unsigned int *) malloc((len + 1) * sizeof(unsigned int));
          if((password == NULL) || (tab == NULL))
            {
              fprintf(stderr, "Error: memory allocation failed.\n\n");
              exit(EXIT_FAILURE);
            }
          strncpy(password, prefix, prefix_len);
          password[prefix_len] = charset[k];
          strncpy(password + prefix_len + 1 + len, suffix, suffix_len);
          password[password_len] = '\0';

          for(i = 0; i <= len; i++)
            tab[i] = 0;

          /* Test all the combinations */
          while((tab[len] == 0) && (stop == 0))
            {
              for(i = 0; i < len; i++)
                password[prefix_len + 1 + i] = charset[tab[len - 1 - i]];

              /* Decrypt the LUKS volume with the password */
              crypt_init(&cd, path);
              crypt_load(cd, CRYPT_LUKS1, NULL);
              ret = crypt_activate_by_passphrase(cd, device_name, CRYPT_ANY_SLOT, password, password_len, CRYPT_ACTIVATE_READONLY);
              /* Note: If the password works but the LUKS volume is already mounted,
                 the crypt_activate_by_passphrase function should return -EBUSY. */
              if((ret >= 0) || (ret == -EBUSY))
                {
                  /* We have a positive result */
                  pthread_mutex_lock(&found_password_lock);
                  printf("Password candidate: %s\n", password);
                  crypt_deactivate(cd, device_name);
                  if(only_one_password)
                    stop = 1;
                  pthread_mutex_unlock(&found_password_lock);
                }
              crypt_free(cd);

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
  fprintf(stderr, "Usage: %s [options] <path>\n\n", progname);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -1           Stop the program after finding the first password candidate.\n");
  fprintf(stderr, "  -b <string>  Beginning of the password.\n");
  fprintf(stderr, "                 default: \"\"\n");
  fprintf(stderr, "  -e <string>  End of the password.\n");
  fprintf(stderr, "                 default: \"\"\n");
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
}

int main(int argc, char **argv)
{
  unsigned int nb_threads = 1;
  pthread_t *decryption_threads;
  unsigned int **indexes;
  int i, ret, c;

  /* Get options and parameters. */
  opterr = 0;
  while((c = getopt(argc, argv, "1b:e:hl:m:s:t:")) != -1)
    switch(c)
      {
      case '1':
        only_one_password = 1;
        break;

      case 'b':
        prefix = optarg;
        break;

      case 'e':
        suffix = optarg;
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
        charset = optarg;
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
      fprintf(stderr, "Error: missing path.\n\n");
      exit(EXIT_FAILURE);
    }

  path = argv[optind];

  /* Check variables */
  if(prefix == NULL)
    prefix = "";
  prefix_len = strlen(prefix);
  if(suffix == NULL)
    suffix = "";
  suffix_len = strlen(suffix);
  if(charset == NULL)
    charset = default_charset;
  charset_len = strlen(charset);
  if(charset_len == 0)
    {
      fprintf(stderr, "Error: charset must have at least one character.\n\n");
      exit(EXIT_FAILURE);
    }
  if(nb_threads > charset_len)
    {
      fprintf(stderr, "Warning: number of threads (%u) bigger than character set length (%u). Only using %u threads.\n\n", nb_threads, charset_len, charset_len);
      nb_threads = charset_len;
    }
  if(min_len < prefix_len + suffix_len + 1)
    {
      fprintf(stderr, "Warning: minimum length (%u) isn't bigger than the length of specified password characters (%u). Setting minimum length to %u.\n\n", min_len, prefix_len + suffix_len, prefix_len + suffix_len + 1);
      min_len = prefix_len + suffix_len + 1;
    }
  if(max_len < min_len)
    {
      fprintf(stderr, "Warning: maximum length (%u) is smaller than minimum length (%u). Setting maximum length to %u.\n\n", max_len, min_len, min_len);
      max_len = min_len;
    }

  /* Check if path points to a LUKS volume */
  ret = check_path(path);
  if(ret == 0)
    {
      fprintf(stderr, "Error: %s is not a valid LUKS volume.\n\n", path);
      exit(EXIT_FAILURE);
    }

  pthread_mutex_init(&found_password_lock, NULL);

  /* Start decryption threads. */
  decryption_threads = (pthread_t *) malloc(nb_threads * sizeof(pthread_t));
  indexes = (unsigned int **) malloc(nb_threads * sizeof(unsigned int *));
  if((decryption_threads == NULL) || (indexes == NULL))
    {
      fprintf(stderr, "Error: memory allocation failed.\n\n");
      exit(EXIT_FAILURE);
    }
  for(i = 0; i < nb_threads; i++)
    {
      indexes[i] = (unsigned int *) malloc(2 * sizeof(unsigned int));
      if(indexes[i] == NULL)
        {
          fprintf(stderr, "Error: memory allocation failed.\n\n");
          exit(EXIT_FAILURE);
        }
      indexes[i][0] = i * (charset_len / nb_threads);
      if(i == nb_threads - 1)
        indexes[i][1] = charset_len - 1;
      else
        indexes[i][1] = (i + 1) * (charset_len / nb_threads) - 1;
      ret = pthread_create(&decryption_threads[i], NULL, &decryption_func, indexes[i]);
      if(ret != 0)
        {
          perror("Error: decryption thread");
          exit(EXIT_FAILURE);
        }
    }

  for(i = 0; i < nb_threads; i++)
    {
      pthread_join(decryption_threads[i], NULL);
      free(indexes[i]);
    }
  free(indexes);
  free(decryption_threads);
  pthread_mutex_destroy(&found_password_lock);

  exit(EXIT_SUCCESS);
}
