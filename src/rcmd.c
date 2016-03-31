#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#define MAX_IPS 128
#define IP_STR_LEN 128
#define OUTPUT_BUF_SIZE 512

/*  int verbosity = SSH_LOG_PROTOCOL; */
const int verbosity = SSH_LOG_NOLOG;
const int port = 22;
long timeout = 30;

uint8_t ips_len = 0;
uint8_t ip_opt = 1;


uint8_t ips[MAX_IPS][IP_STR_LEN];
char *cmd_opt, *key_opt, *login_opt, *timeout_opt;


static int extract_ips(char ips_opt[])
{
  uint32_t ip, i, j, c;

  for (i=0, ip=0, j=0; (c = ips_opt[i]) != '\0'; ++i) {
    if (ip >= MAX_IPS) {
      fprintf(stderr, "Max IPs is %d\n", MAX_IPS);
      return -1;
    }

    if (c == ',') {
      ips[ip++][j] = '\0';
      j = 0;
    } else {
      ips[ip][j++] = c;
    }
  }

  ips[ip][j+1] = '\0';
  ips_len = ip+1;

  return 0;
}

static void usage()
{
  printf("usage: rcmd [-H hosts] [-c remote_command]\n"
         "            [-k path/to/private_key]\n"
         "            [-l login_name]\n"
         "            [-t timeout]\n"
         );
}



static int extract_opts(int argc, char **argv)
{
  int16_t c;
  cmd_opt = key_opt = login_opt = NULL;

  while ((c = getopt(argc, argv, "H:l:c:k:t:qh")) != -1)
    switch(c) {
    case 'H':
      if (extract_ips(optarg) != 0)
        return -1;
      break;
    case 'c':
      cmd_opt = optarg;
      break;
    case 'k':
      key_opt = optarg;
      break;
    case 'l':
      login_opt = optarg;
      break;
    case 'q':
      ip_opt = 0;
      break;
    case 't':
      timeout = (long) *optarg - '0';
      break;
    case 'h':
      usage();
      break;
    }

  if (key_opt == NULL)
    key_opt = getenv("RCMD_PK_PATH");

  if (login_opt == NULL)
    login_opt = getenv("RCMD_LOGIN");

  return 0;
}

static int32_t close_channel(ssh_channel ch)
{
  ssh_channel_close(ch);
  ssh_channel_free(ch);
  return SSH_OK;
}

static int32_t run_cmd(ssh_session session, char *ip_addr)
{
  ssh_channel ch;
  uint8_t buf[OUTPUT_BUF_SIZE];
  int32_t rc, nbytes, is_stderr = 0;

  ch = ssh_channel_new(session);

  if (ch == NULL)
    return SSH_ERROR;

  rc = ssh_channel_open_session(ch);

  if (rc != SSH_OK) {
    ssh_channel_free(ch);
    return rc;
  }

  rc = ssh_channel_request_exec(ch, cmd_opt);

  if (rc != SSH_OK) {
    close_channel(ch);
    return rc;
  }

  nbytes = ssh_channel_read(ch, buf, OUTPUT_BUF_SIZE, is_stderr);
  if (nbytes == 0) {
    is_stderr = 1;
    nbytes = ssh_channel_read(ch, buf, OUTPUT_BUF_SIZE, is_stderr);
  }

  while (nbytes > 0) {
    if (ip_opt)
      printf("\e[32m%s:\e[39m\n", ip_addr);

    if (write(1, buf, nbytes) != (unsigned int) nbytes) {
      close_channel(ch);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(ch, buf, OUTPUT_BUF_SIZE, is_stderr);
  }

  if (nbytes < 0) {
    close_channel(ch);
    return SSH_ERROR;
  }

  ssh_channel_send_eof(ch);
  close_channel(ch);

  return SSH_OK;
}

static void *ssh_exec(void *ip)
{
  int8_t conn;
  char *ip_addr;
  ssh_key k;
  ssh_session session = ssh_new();

  ip_addr = (char *) ip;

  if (session == NULL)
    fprintf(stderr, "error: session null\n");

  ssh_options_set(session, SSH_OPTIONS_USER, login_opt);
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
  } else {
    run_cmd(session, ip_addr);
  }

  ssh_key_free(k);
  ssh_disconnect(session);
  ssh_free(session);

  return NULL;
}

int main(int32_t argc, char **argv)
{
  if (extract_opts(argc, argv) != -1) {
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();

    int32_t i, t;
    pthread_t threads[ips_len];

    for (i=0; i < ips_len; i++) {
      t = pthread_create(&threads[i], NULL, ssh_exec, (void*) ips[i]);
      if(t) {
        fprintf(stderr,"Error - pthread_create() return code: %d\n", t);
      }
    }

    for (i=0; i<ips_len; i++) {
      t = pthread_join(threads[i], NULL);
    }

    exit(EXIT_SUCCESS);
  } else {
    exit(EXIT_FAILURE);
  }
}
