/*
 * dummy-init.c
 *
 * sleep forever and exit on SIGTERM signal
 *
 * Author: Yanke Guo <guoyk.cn@gmail.com>
 */

#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static void sighandler(int sig) {
  exit(0);
}

int main() {
  // handle SIGTERM and exit(0)
  struct sigaction sa;
  sa.sa_handler =  sighandler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);

  // pause forever
  for(;;) {
    pause();
  }
}

