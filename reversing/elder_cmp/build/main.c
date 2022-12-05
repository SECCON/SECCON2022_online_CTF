#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <asm/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#pragma GCC push_options
#pragma GCC optimize ("O0")
unsigned char baby_mode = 0;
#pragma GCC pop_options

#define arch_prctl(code, addr)                            \
  asm volatile("movq %1, %%rsi;"                          \
               "movl %0, %%edi;"                          \
               "mov $158, %%eax;"                         \
               "syscall;"                                 \
               : : "r"(code), "r"(addr)                   \
               : "%rax", "%rcx", "%rdi", "%rsi", "%r11");
#define cpuid(arg)                                \
  asm volatile("mov %0, %%rdi;"                   \
               "cpuid;"                           \
               : : "r"(arg)                       \
               : "%rax", "%rbx", "%rcx", "%rdx");
#define clts(arg)                                 \
  asm volatile("mov %0, %%rdi;"                   \
               "clts;"                            \
               : : "r"(arg));
#define skip() asm volatile("hlt"); // Obfuscator

#define DEF_AUTOMATON(FUNC_NAME)                \
  void FUNC_NAME(local_t *__stk, void *__next)
#define LOCAL (__stk)
#define NEXT(LABEL)                             \
  __next = &&LABEL;                             \
  goto next
#define NEXT_STATE()                            \
  next:                                         \
  arch_prctl(ARCH_SET_GS, __next);              \
  clts(__stk)
#define DEFINE_STATE(L)                         \
  __asm__ goto (""::::L);
#define LABEL(L)                                \
  L:

//#define debug(msg) puts("[DEBUG] " msg);
#define debug(msg)

/* Stack variables */
typedef struct {
  char *flag;
  size_t len, cur;

  struct {
    unsigned char wrong[9];
    unsigned char correct[9];
  } str;

  struct {
    unsigned char S[0x10];
    unsigned char plain_key[32];
    unsigned char roundconst[36];
    unsigned char rk[36][8];
  } key;
} local_t;

DEF_AUTOMATON(heart) {
  /* Define states */
  DEFINE_STATE(st_start);
  DEFINE_STATE(st_expand_key);
  DEFINE_STATE(st_encrypt);
  DEFINE_STATE(st_compare);
  DEFINE_STATE(st_fail);
  DEFINE_STATE(st_correct);
  DEFINE_STATE(st_cleanup);
  NEXT(st_start);

  /* Setup */
  LABEL(st_start) {
    debug("st_start");
    LOCAL->cur = 0;
    strcpy(LOCAL->str.wrong, "Vsnof///");
    strcpy(LOCAL->str.correct, "Bnssdbu ");
    memcpy(LOCAL->key.plain_key,
           "\x11\x45\x14\x19\x19\x81\x09\x31"
           "\x88\x94\x64\x51\x28\x10\x93\x15",
           0x10);
    memcpy(LOCAL->key.S,
           "\x0C\x00\x0F\x0A\x02\x0B\x09\x05\x08\x03\x0D\x07\x01\x0E\x06\x04",
           0x10);
    memcpy(LOCAL->key.roundconst,
           "\x01\x02\x04\x08\x10\x20\x03\x06\x0c\x18\x30\x23"
           "\x05\x0a\x14\x28\x13\x26\x0f\x1e\x3c\x3b\x35\x29"
           "\x11\x22\x07\x0e\x1c\x38\x33\x25\x09\x12\x24\x0b",
           36);
    NEXT(st_expand_key);
  }

  /* Expand keys 128 */
  LABEL(st_expand_key) {
    debug("st_expand_key");
    int wk[32];
    for (int i = 0; i < 16; i++) {
      wk[2*i] = LOCAL->key.plain_key[i] >> 4;
      wk[2*i+1] = LOCAL->key.plain_key[i] & 0x0f;
      skip();
    }
    for (int i = 0; i < 35; i++) {
      LOCAL->key.rk[i][0] = wk[31];
      LOCAL->key.rk[i][1] = wk[28];
      LOCAL->key.rk[i][2] = wk[18];
      LOCAL->key.rk[i][3] = wk[17];
      LOCAL->key.rk[i][4] = wk[15];
      LOCAL->key.rk[i][5] = wk[12];
      LOCAL->key.rk[i][6] = wk[3];
      LOCAL->key.rk[i][7] = wk[2];
      wk[1] ^= LOCAL->key.S[wk[30]];
      wk[4] ^= LOCAL->key.S[wk[16]];
      wk[23] ^= LOCAL->key.S[wk[0]];
      unsigned char con = LOCAL->key.roundconst[i];
      wk[19] ^= con >> 3;
      wk[7] ^= con & 7;
      skip();

      int tmp0 = wk[0];
      int tmp1 = wk[1];
      int tmp2 = wk[2];
      int tmp3 = wk[3];
      for (int j = 0; j < 7; j++) {
        int fourj = j * 4;
        wk[fourj] = wk[fourj + 4];
        wk[fourj + 1] = wk[fourj + 5];
        wk[fourj + 2] = wk[fourj + 6];
        wk[fourj + 3] = wk[fourj + 7];
        skip();
      }
      wk[28] = tmp1;
      wk[29] = tmp2;
      wk[30] = tmp3;
      wk[31] = tmp0;
      skip();
    }

    LOCAL->key.rk[35][0] = wk[3];
    LOCAL->key.rk[35][1] = wk[2];
    LOCAL->key.rk[35][2] = wk[15];
    LOCAL->key.rk[35][3] = wk[12];
    LOCAL->key.rk[35][4] = wk[18];
    LOCAL->key.rk[35][5] = wk[17];
    LOCAL->key.rk[35][6] = wk[31];
    LOCAL->key.rk[35][7] = wk[28];
    NEXT(st_encrypt);
  }

  /* Encryption */
  LABEL(st_encrypt) {
    debug("st_encrypt");
    unsigned char x[16], *src;
    src = &LOCAL->flag[LOCAL->cur];

    char shuf[] = {5, 0, 1, 4, 7, 12, 3, 8, 13, 6, 9, 2, 15, 10, 11, 14};
    for (int i = 0; i < 8; i++) {
      x[2*i] = src[i] >> 4;
      x[2*i+1] = src[i] & 0x0f;
      skip();
    }

    for (int i = 0; i < 35; i++) {
      for (int j = 0; j < 8; j++) {
        x[2*j+1] ^= LOCAL->key.S[x[2*j] ^ LOCAL->key.rk[i][j]];
        skip();
      }

      unsigned char xnext[16];
      for (int h = 0; h < 16; h++) {
        xnext[shuf[h]] = x[h];
      }

      memcpy(x, xnext, sizeof(x));
      skip();
    }

    for (int j = 0; j < 8; j++) {
      x[2*j+1] ^= LOCAL->key.S[x[2*j] ^ LOCAL->key.rk[35][j]];
      skip();
    }

    for (int i = 0; i < 8; i++) {
      src[i] = (x[2*i] << 4) | x[2*i+1];
      skip();
    }

    NEXT(st_compare);
  }

  /* Comparison */
  LABEL(st_compare) {
    debug("st_compare");

    unsigned long w;
    unsigned long v = *(unsigned long*)&LOCAL->flag[LOCAL->cur];
    switch (LOCAL->cur) {
      case 0x00:
        w = 0x5894a5af7f7693b7;
        break;
      case 0x08:
        w = 0x94706b86ce8e1cce;
        break;
      case 0x10:
        w = 0x0098ba6f1ff3cc98;
        break;
      case 0x18:
        w = 0x0ae6575961af354c;
        break;
      case 0x20:
        w = 0xd853f981df45ab41;
        break;
      case 0x28:
        w = 0xe1fefd554e662f7f;
        break;
      case 0x30:
        w = 0x3ca11fb09e498ab4;
        break;
      default: {
        NEXT(st_fail);
      }
    }

    if (v != w) {
      NEXT(st_fail);
    }

    LOCAL->cur += 8;
    if (LOCAL->cur >= LOCAL->len) {
      if (LOCAL->cur == 0x38) {
        NEXT(st_correct);
      } else {
        NEXT(st_fail);
      }
    } else {
      NEXT(st_encrypt);
    }
  }

  /* Wrong flag */
  LABEL(st_fail) {
    debug("st_fail");
    for (int i = 0; i < sizeof(LOCAL->str.wrong) - 1; i++)
      LOCAL->str.wrong[i] ^= 1;
    puts(LOCAL->str.wrong);
    NEXT(st_cleanup);
  }

  /* Correct flag */
  LABEL(st_correct) {
    debug("st_correct");
    for (int i = 0; i < sizeof(LOCAL->str.correct) - 1; i++)
      LOCAL->str.correct[i] ^= 1;
    puts(LOCAL->str.correct);
    NEXT(st_cleanup);
  }

  /* Cleanup */
  LABEL(st_cleanup) {
    debug("st_debug");
    free(LOCAL->flag);
    free(LOCAL);
    exit(0);
  }

  NEXT_STATE();
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s FLAG\n", argv[0]);
    return 1;
  }

  cpuid(argv[1]);

  const char enc[] = "\x04\x20\x2f\x20\x20\x23\x1e\x59\x44\x1a\x7f\x35\x75\x36\x2d\x2b\x11\x17\x5a\x03\x6d\x50\x36\x07\x15\x3c\x09\x01\x04\x47\x2b\x36\x41\x0a\x38";
  const char key[] = "Welcome to SECCON 2022";
  size_t len = strlen(argv[1]);
  for (int i = 0; i < len; i++) {
    argv[1][i] ^= key[i % (sizeof(key)-1)];
  }
  if (memcmp(argv[1], enc, sizeof(enc)) == 0) {
    puts("Correct!");
  } else {
    puts("Wrong...");
  }

  return 0;
}

/* This trampoline is called on every SIGSEGV */
static void trampoline(int sig, siginfo_t *si, void *uc_void) {
  ucontext_t *uc = (ucontext_t*)uc_void;
  void *rip = (void*)uc->uc_mcontext.gregs[REG_RIP];

  if (*(unsigned char*)rip == 0xf4) {
    /* Called by HLT, then skip the instruction (NOP) */
    uc->uc_mcontext.gregs[REG_RIP] += 1;

  } else if (*(unsigned char*)rip == 0x0f) {
    /* Called by CLTS or CPUID */
    // Dangerously align RSP
    uc->uc_mcontext.gregs[REG_RSP] &= ~0xf;

    // GS should point to the address to jump
    arch_prctl(ARCH_GET_GS, &uc->uc_mcontext.gregs[REG_RIP]);

    if (*(unsigned char*)(rip + 1) == 0xa2) {
      /* Called by CPUID, then create context */
      local_t *local = (local_t*)malloc(sizeof(local_t));

      // Add padding to flag
      char *flag = (char*)uc->uc_mcontext.gregs[REG_RDI];
      size_t len_flag = strlen(flag);
      size_t len = (len_flag + 8) & 0xf8;
      local->flag = (char*)malloc(len);
      strcpy(local->flag, flag);
      for (size_t i = len_flag; i < len; i++)
        local->flag[i] = len - len_flag;
      local->len = len;

      uc->uc_mcontext.gregs[REG_RDI] = (greg_t)local;
    } else if (*(unsigned char*)(rip + 1) != 0x06) {
      goto fail;
    }

  } else {
    goto fail;
  }

  return;

 fail:
  /* Otherwise kill */
  exit(1);
}

__attribute__((constructor))
void __detect_debugger(void) {
  struct sigaction sa;

  if (!baby_mode) {
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = trampoline;
    sigaction(SIGSEGV, &sa, NULL);
    arch_prctl(ARCH_SET_CPUID, 0UL);
    arch_prctl(ARCH_SET_GS, heart);
  }
}
