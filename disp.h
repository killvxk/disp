#ifndef DISP_H
#define DISP_H

void disp_init();

#define INLINE inline __attribute__((always_inline))

static INLINE void _clflush(void *v) {
  asm volatile ("clflush 0(%0)": : "r" (v):);
}

#endif
