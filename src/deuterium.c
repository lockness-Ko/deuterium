#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "deuterium.skel.h"

static void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
    .rlim_cur = RLIM_INFINITY,
    .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

int main(void) {
  bump_memlock_rlimit();

  struct deuterium *skel = deuterium__open();
  deuterium__load(skel);
  deuterium__attach(skel);

  for(;;) {}
  return 0;
}
