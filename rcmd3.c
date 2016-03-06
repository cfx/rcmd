#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_IPS 128
#define IP_LEN 16

char ips[MAX_IPS][IP_LEN];

int extract_ips(char ips_opt[])
{
  int h, i, j, c;

  for (i=0, h=0, j=0; (c = ips_opt[i]) != '\0'; ++i) {
    if (i >= MAX_IPS) {
      fprintf(stderr, "Max IPs is %d\n", MAX_IPS);
      return 1;
    }

    if (c == ',') {
      ips[h++][j] = '\0';
      j = 0;
    } else {
      ips[h][j++] = c;
    }

    if (j > IP_LEN) {
      fprintf(stderr, "Incorrect IP in -h option.\n");
      return 1;
    }
  }

  ips[h][j+1] = '\0';
  return 0;
}

int main(int argc, char **argv)
{
  int c, i, j;
  char *cmd_opt, *key_opt;

  cmd_opt = key_opt = NULL;

  while ((c = getopt(argc, argv, "h:ck")) != -1)
    switch(c) {
    case 'h':
      if (extract_ips(optarg) == 1)
        return 1;
      break;
    case 'c':
      cmd_opt = optarg;
      break;
    case 'k':
      key_opt = optarg;
      break;
    case '?':
      printf("woof");
      return 1;
    }

  for (i=0; ips[i][0] != '\0'; ++i) {
    for (j=0; ips[i][j] != '\0'; ++j) {
      printf("%c", ips[i][j]);
    }
    printf("\n");
  }

  return 0;
}
