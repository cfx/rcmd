#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>


// gcc -o rcmd3 -DDEBUG=9 -pedantic -Wall -g rcmd3.c -lssh -lssh_threads
// ./rcmd3 -h 54.146.159.150,107.22.64.54


#define MAX_IPS 128
#define IP_STR_LEN 16
#define OUTPUT_BUF_SIZE 512

/*  int verbosity = SSH_LOG_PROTOCOL; */
const int verbosity = SSH_LOG_NOLOG;
const int port = 22;

int ips_len = 0;
int ip_opt = 1;
long timeout = 30;

char ips[MAX_IPS][IP_STR_LEN];
char *cmd_opt, *key_opt, *user_opt, *timeout_opt;

int extract_ips(char ips_opt[])
{
  int ip, i, j, c;

  for (i=0, ip=0, j=0; (c = ips_opt[i]) != '\0'; ++i) {
    if (ip >= MAX_IPS) {
      fprintf(stderr, "Max IPs is %d\n", MAX_IPS);
      return 1;
    }

    if (c == ',') {
      ips[ip++][j] = '\0';
      j = 0;
    } else {
      ips[ip][j++] = c;
    }

    if (j > IP_STR_LEN) {
      fprintf(stderr, "Incorrect IP in -h option.\n");
      return 1;
    }
  }

  ips[ip][j+1] = '\0';
  ips_len = ip+1;

  return 0;
}


int extract_opts(int argc, char **argv)
{
  int c;
  cmd_opt = key_opt = user_opt = NULL;

  while ((c = getopt(argc, argv, "h:u:c:k:t:q")) != -1)
    switch(c) {
    case 'h':
      if (extract_ips(optarg) != 0)
        return -1;
      break;
    case 'c':
      cmd_opt = optarg;
      break;
    case 'k':
      key_opt = optarg;
      break;
    case 'u':
      user_opt = optarg;
      break;
    case 'q':
      ip_opt = 0;
      break;
    case 't':
      timeout = (long) *optarg - '0';
      break;
    case '?':
      printf("woof");
      return -1;
    }

  if (key_opt == NULL)
    key_opt = getenv("RCMD_PK_PATH");

  if (user_opt == NULL)
    user_opt = getenv("RCMD_USER");

  return 0;
}


int run_cmd(ssh_session session, char *ip_addr)
{
  ssh_channel channel;
  int rc;
  char buf[OUTPUT_BUF_SIZE];
  int nbytes;

  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;

  rc = ssh_channel_open_session(channel);

  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }

  rc = ssh_channel_request_exec(channel, cmd_opt);

  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }

  while ((nbytes = ssh_channel_read(channel, buf, OUTPUT_BUF_SIZE, 0)) > 0)
  {

    if (ip_opt)
      printf("\e[32m%s:\e[39m\n", ip_addr);

    if (write(1, buf, nbytes) != (unsigned int) nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
  }

  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }

  //printf("\n\n%d\n\n", nbytes);
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return SSH_OK;
}

static void *ssh_exec(void *ip)
{
  int conn;
  char *ip_addr;
  ssh_key k;
  ssh_session session = ssh_new();

  ip_addr = (char *) ip;

  if (session == NULL)
    fprintf(stderr, "error: session null\n");

  ssh_options_set(session, SSH_OPTIONS_USER, user_opt);
  ssh_options_set(session, SSH_OPTIONS_HOST, ip_addr);
  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  ssh_options_set(session, SSH_OPTIONS_PORT, &port);
  ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

  conn = ssh_connect(session);

  if (conn != SSH_OK) {
    fprintf(stderr, "Connection error: %s\n", ssh_get_error(session));
  }

  if (ssh_pki_import_privkey_file(key_opt, NULL, NULL, NULL, &k) != SSH_OK) {
    fprintf(stderr, "SSH private key problem: %s\n", key_opt);
  }

  if (ssh_userauth_publickey(session, NULL, k) != SSH_AUTH_SUCCESS) {
    fprintf(stderr, "error: %s (%s)\n\n", ssh_get_error(session), ip_addr);
  }

  run_cmd(session, ip_addr);

  ssh_key_free(k);
  ssh_disconnect(session);
  ssh_free(session);

  return NULL;
}

int main(int argc, char **argv)
{
  if (extract_opts(argc, argv) != -1) {
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();

    int i, t;
    pthread_t threads[ips_len];

    for (i=0; i < ips_len; i++) {
      t = pthread_create(&threads[i], NULL, ssh_exec, (void*) ips[i]);
      if(t) {
        fprintf(stderr,"Error - pthread_create() return code: %d\n",t);
      }
    }

    for (i=0; i<ips_len; i++) {
      t = pthread_join(threads[i], NULL);
    }
  }

  exit(EXIT_SUCCESS);
}
