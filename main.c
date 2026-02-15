#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(){
  
  int ret;
  cpu_set_t cpu_set;

  CPU_ZERO(&cpu_set);
  CPU_SET(17, &cpu_set);

  ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
  if (ret){
    int err = errno;
    char* e_str = strerror(err);
    printf("%d", err);
    printf("%s", e_str);
  }

  
  return 0;
}
