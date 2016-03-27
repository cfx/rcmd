## rcmd

`rcmd` allows to execute any shell command over ssh on multiple remote machines.

### Prerequisites

`rcmd` is dependent on `libssh` library [ https://www.libssh.org/ ]


### Installation

```bash
$ ./autogen.sh
$ ./configure
$ make
$ [sudo] make install
```

### Usage

```bash
$ rcmd -H 55.88.71.140,55.88.71.141 -l login_name -k 'path/to/private_key' -c 'hostname'
```

You can specify login and path to private key as env variables e.g:

```bash
RCMD_LOGIN=cfx
RCMD_PK_PATH=/Users/cfx/.ssh/my_pk.pem
```
