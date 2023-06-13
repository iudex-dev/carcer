#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <wait.h>

// Globals /////////////////////////////////////////////////////////////////////

struct {
  struct timeval start_time;
  struct timeval end_time;
  pid_t child_pid;
} Globals;

struct {
  const char *exe_path;
  const char *input_file;
  const char *output_file;
  const char *error_file;
  int uid;
  int gid;
  int max_real_time_ms;
  int max_cpu_s;
  int max_memory_KB;
  int max_output_size_KB;
} Config;

struct {
  int cpu_time_ms;
  int real_time_ms;
  long memory;
  int signal;
  int exit_code;
  int error;
  int report;
  char *reason;
} Results;

// Errors //////////////////////////////////////////////////////////////////////

void fatal(int code, const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
}

// Arguments ///////////////////////////////////////////////////////////////////

static const char *usage =
    "usage: carcer [<opts>...] <exe_path>\n"
    "\n"
    "  Execute a binary with seccomp syscall filters.\n"
    "\n"
    "Options:\n"
    "  -i, --stdin <file>  File to use as stdin\n"
    "  -o, --stdout <file> File to use as stdout\n"
    "  -e, --stder <file>  File to use as stderr\n"
    "  -u, --uid <n>       Run as user ID <n>\n"
    "  -g, --gid <n>       Run as group ID <n>\n"
    "  -m, --mem <m>       Limit memory to <m> in KBs       [default = 100]\n"
    "  -c, --cpu <c>       Limit CPU time to <c> in seconds [default = 5]\n"
    "  -r, --real <r>      Limit real time to <r> in ms     [default = 5000]\n"
    "  -s, --out-size <o>  Limit output size to <o> in KBs  [default = 10]\n"
    "\n";

bool is_opt(const char *arg) { return arg[0] == '-'; }

bool is_opt_short(const char *arg, char opt) {
  return (is_opt(arg) ? arg[1] == opt : false);
}

int max(int a, int b) { return a >= b ? a : b; }

bool is_opt_long(const char *arg, char *opt) {
  if (arg[0] == '-' && arg[1] == '-') {
    int maxlen = max(strlen(arg + 2), strlen(opt));
    return 0 == strncmp(arg + 2, opt, maxlen);
  }
  return false;
}

void assign_if_parse_int(const char *opt, const char *str, int *out) {
  int number;
  if (1 == sscanf(str, "%d", &number)) {
    *out = number;
  } else {
    char msg[256];
    snprintf(msg, sizeof(msg), "Expected a number for option '%s'", opt);
    fatal(21, msg);
  }
}

void parse_args(int argc, const char *const argv[]) {
#define NEXT()                                                                 \
  if (++i >= argc)                                                             \
  break

  int i = 1;
  while (i < argc) {
    if (is_opt_short(argv[i], 'h') || is_opt_long(argv[i], "help")) {
      printf("%s", usage);
      exit(0);
    } else if (is_opt_short(argv[i], 'i') || is_opt_long(argv[i], "stdin")) {
      NEXT();
      Config.input_file = argv[i];
    } else if (is_opt_short(argv[i], 'o') || is_opt_long(argv[i], "stdout")) {
      NEXT();
      Config.output_file = argv[i];
    } else if (is_opt_short(argv[i], 'e') || is_opt_long(argv[i], "stderr")) {
      NEXT();
      Config.error_file = argv[i];
    } else if (is_opt_short(argv[i], 'u') || is_opt_long(argv[i], "uid")) {
      NEXT();
      assign_if_parse_int("uid", argv[i], &Config.uid);
    } else if (is_opt_short(argv[i], 'g') || is_opt_long(argv[i], "gid")) {
      NEXT();
      assign_if_parse_int("gid", argv[i], &Config.gid);
    } else if (is_opt_short(argv[i], 'm') || is_opt_long(argv[i], "mem")) {
      NEXT();
      assign_if_parse_int("mem", argv[i], &Config.max_memory_KB);
    } else if (is_opt_short(argv[i], 'c') || is_opt_long(argv[i], "cpu")) {
      NEXT();
      assign_if_parse_int("cpu", argv[i], &Config.max_cpu_s);
    } else if (is_opt_short(argv[i], 'r') || is_opt_long(argv[i], "real")) {
      NEXT();
      assign_if_parse_int("real", argv[i], &Config.max_real_time_ms);
    } else if (is_opt_short(argv[i], 's') || is_opt_long(argv[i], "out-size")) {
      NEXT();
      assign_if_parse_int("out-size", argv[i], &Config.max_output_size_KB);
    } else if (is_opt(argv[i])) {
      char msg[256];
      snprintf(msg, sizeof(msg), "Unknown option '%s'", argv[i]);
      fatal(20, msg);
    } else {
      Config.exe_path = argv[i];
    }

    i++;
  }

#undef NEXT
}

// Reports /////////////////////////////////////////////////////////////////////

#define ALL_REPORT_VALUES                                                      \
  REPORT_VALUE(0, RUN_OK, "Ok")                                                \
  REPORT_VALUE(1, SEGMENTATION_FAULT, "Segmentation Fault")                    \
  REPORT_VALUE(2, BAD_SYSTEM_CALL, "Bad system call")                          \
  REPORT_VALUE(3, CPU_LIMIT_EXCEEDED, "CPU limit exceeded")                    \
  REPORT_VALUE(4, TIME_LIMIT_EXCEEDED, "Time limit exceeded")                  \
  REPORT_VALUE(5, MEMORY_LIMIT_EXCEEDED, "Memory limit exceeded")              \
  REPORT_VALUE(6, OUTPUT_SIZE_EXCEEDED, "Output size exceeded")                \
  REPORT_VALUE(255, SYSTEM_ERROR, "System error")

typedef enum {
#define REPORT_VALUE(n, var, _) var = n,
  ALL_REPORT_VALUES
#undef REPORT_VALUE
} VeredictValue;

const char *report_message[] = {
#define REPORT_VALUE(_, __, msg) msg,
    ALL_REPORT_VALUES
#undef REPORT_VALUE
};

// Child Process ///////////////////////////////////////////////////////////////

void limit_resource(char *name, __rlimit_resource_t res_id, rlim_t value) {
  struct rlimit bounds;
  bounds.rlim_cur = value;
  bounds.rlim_max = value;
  if (setrlimit(res_id, &bounds) != 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "Couldn't setrlimit: %s", name);
    fatal(5, msg);
  }
}

void set_uid(uid_t uid) {
  if (setuid(uid) == -1) {
    fatal(9, "Couldn't set uid");
  }
}

void set_gid(uid_t gid) {
  if (setgid(gid) == -1) {
    fatal(9, "Couldn't set gid");
  }
  uid_t group_list[] = {gid};
  if (setgroups(sizeof(group_list) / sizeof(gid_t), group_list) == -1) {
    fatal(10, "Couldn't set groups");
  }
}

const int syscall_whitelist[] = {
    // Necessary for clang and gcc compiled programs
    SCMP_SYS(arch_prctl),
    SCMP_SYS(brk),  // Memory allocation
    SCMP_SYS(mmap), // Memory allocation

    SCMP_SYS(set_tid_address), // Threading
    SCMP_SYS(set_robust_list), // Threading

    SCMP_SYS(rseq),  // TCMalloc (https://google.github.io/tcmalloc/rseq.html)
    SCMP_SYS(uname), // ???
    SCMP_SYS(prlimit64),  // set stack size
    SCMP_SYS(readlink),   // access /proc/self/exe (why?)
    SCMP_SYS(mprotect),   // Change memory props
    SCMP_SYS(newfstatat), // Check stdin?
    SCMP_SYS(getrandom),  // ???
    SCMP_SYS(lseek),      // ??? (add_numbers.c)

    // C++ programs
    SCMP_SYS(futex),

    // Minimal: 1) read from stdin, 2) write to stdout, and 3) exit
    SCMP_SYS(read),
    SCMP_SYS(write),
    SCMP_SYS(writev),
    SCMP_SYS(exit_group),
};
const int whitelist_size = sizeof(syscall_whitelist) / sizeof(int);

void whitelist_syscall(scmp_filter_ctx ctx, int nsyscall) {
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nsyscall, 0) != 0) {
    char msg[256];
    char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, nsyscall);
    snprintf(msg, sizeof(msg), "Couldn't white list '%s'", name);
    fatal(11, msg);
  }
}

void whitelist_execve(scmp_filter_ctx ctx) {
  if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1,
                       SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)Config.exe_path))) {
    fatal(12, "Couldn't set rule for 'execve'");
  }
}

void whitelist_open(scmp_filter_ctx ctx) {
  const int open_result =
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,
                       SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0));
  if (open_result != 0) {
    fatal(12, "Could not add rule for 'open'");
  }
}

void whitelist_openat(scmp_filter_ctx ctx) {
  const int openat_result =
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 1,
                       SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY | O_RDWR, 0));
  if (openat_result != 0) {
    fatal(12, "Could not add rule for 'openat'");
  }
}

void load_seccomp_filter() {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  if (ctx == NULL) {
    fatal(11, "Could not init seccomp");
  }

  for (int i = 0; i < whitelist_size; i++) {
    whitelist_syscall(ctx, syscall_whitelist[i]);
  }
  whitelist_execve(ctx);
  // whitelist_open(ctx);
  // whitelist_openat(ctx);

  if (seccomp_load(ctx) < 0) {
    fatal(13, "Could not load seccomp filter");
  }

  seccomp_release(ctx);
}

void assign_io(int fd, const char *path, char *mode) {
  if (path == NULL) {
    return;
  }
  assert(fd >= 0 && fd <= 2);
  static const char *std_fds[] = {"stdin", "stdout", "stderr"};
  FILE *file = fopen(path, mode);
  if (file == NULL) {
    char msg[256];
    snprintf(msg, sizeof(msg), "Couldn't open '%s'", path);
    fatal(7, msg);
  }
  if (dup2(fileno(file), fd) == -1) {
    char msg[1024];
    snprintf(msg, sizeof(msg), "Couldn't dup2 '%s': %s", std_fds[fd],
             strerror(errno));
    fatal(8, msg);
  }
}

void child_process() {
  limit_resource("cpu", RLIMIT_CPU, Config.max_cpu_s);
  limit_resource("memory", RLIMIT_AS, Config.max_memory_KB * 1024);
  limit_resource("output_size", RLIMIT_FSIZE, Config.max_output_size_KB * 1024);

  assign_io(STDIN_FILENO, Config.input_file, "r");
  assign_io(STDOUT_FILENO, Config.output_file, "w");
  assign_io(STDERR_FILENO, Config.error_file, "w");

  if (Config.uid >= 0) {
    set_uid((uid_t)Config.uid);
  }
  if (Config.gid >= 0) {
    set_gid((uid_t)Config.gid);
  }

  load_seccomp_filter();

  char *const args[] = {(char *const)Config.exe_path};
  char *const env[] = {NULL};
  execve(Config.exe_path, args, env);
  printf("kk!");
  fatal(14, "Could not execve process");
}

// Terminator Thread ///////////////////////////////////////////////////////////

typedef struct {
  int timeout;
  int child_pid;
} terminator_args_t;

void *terminator_thread(void *args) {
  terminator_args_t *targs = (terminator_args_t *)args;
  if (pthread_detach(pthread_self()) != 0) {
    fprintf(stderr, "Terminator: cannot thread_detach\n");
    kill(targs->child_pid, SIGKILL);
    return NULL;
  }
  const unsigned int seconds = (targs->timeout + 1000) / 1000;
  if (sleep(seconds) != 0) {
    fprintf(stderr, "Terminator: cannot sleep %d seconds\n", seconds);
    kill(targs->child_pid, SIGKILL);
    return NULL;
  }
  fprintf(stderr, "Killing process %d... ", targs->child_pid);
  kill(targs->child_pid, SIGKILL);
  fprintf(stderr, "done\n");
  return NULL;
}

// Parent Process //////////////////////////////////////////////////////////////

int to_ms(struct timeval *t) { return t->tv_sec * 1000 + t->tv_usec / 1000; }

int compute_cpu_time(struct rusage *usage) { return to_ms(&usage->ru_utime); }

void parent_process() {
  pthread_t tid = 0;
  terminator_args_t args = {.timeout = Config.max_real_time_ms,
                            .child_pid = Globals.child_pid};
  if (pthread_create(&tid, NULL, terminator_thread, (void *)&args) != 0) {
    kill(Globals.child_pid, SIGKILL);
    fatal(15, "Couldn't create terminator thread");
  }

  int status;
  struct rusage resource_usage;

  if (wait4(Globals.child_pid, &status, WSTOPPED, &resource_usage) == -1) {
    kill(Globals.child_pid, SIGKILL);
    fatal(16, "Wait for child failed");
  }
  gettimeofday(&Globals.end_time, NULL);

  if (pthread_cancel(tid) != 0) {
    fatal(16, "Couldn't cancel terminator thread");
  }

  if (WIFEXITED(status)) {
    Results.exit_code = WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status) != 0) {
    Results.signal = WTERMSIG(status);
  }

  // Gather results
  Results.cpu_time_ms = to_ms(&resource_usage.ru_utime);
  Results.real_time_ms = to_ms(&Globals.end_time) - to_ms(&Globals.start_time);
  Results.memory = resource_usage.ru_maxrss; // both in KB (see getrusage(2))

  // Find out report
  Results.report = SYSTEM_ERROR; // presumption

  switch (Results.signal) {
  case SIGSYS:
    Results.report = BAD_SYSTEM_CALL;
    return;
  case SIGSEGV:
    //
    // We cannot know if the process allocated memory above the limit because
    // malloc simply doesn't return more memory and gives an error. But if the
    // process was killed it could be because it tried to access memory above
    // the limit, and we can check that here.
    //   -- @pauek
    //
    if (Results.memory > Config.max_memory_KB) {
      Results.report = MEMORY_LIMIT_EXCEEDED;
      return;
    }
    Results.report = SEGMENTATION_FAULT;
    return;
  case SIGXFSZ:
    Results.report = OUTPUT_SIZE_EXCEEDED;
    return;
  case SIGKILL:
    // killed by The Terminator(TM) or by setrlimit
    Results.report = TIME_LIMIT_EXCEEDED;
    return;
  }

  if (Results.real_time_ms > Config.max_real_time_ms) {
    Results.report = TIME_LIMIT_EXCEEDED;
  }
  if (Results.cpu_time_ms > Config.max_cpu_s * 1000) {
    Results.report = CPU_LIMIT_EXCEEDED;
  }

  Results.report = RUN_OK;
}

// main ////////////////////////////////////////////////////////////////////////

void do_fork() {
  gettimeofday(&Globals.start_time, NULL);
  pid_t child_pid = fork();
  switch (child_pid) {
  case -1:
    fatal(3, strcat("Couldn't fork process: ", strerror(errno)));
  case 0:
    child_process(); // does not return since does an 'execve'
  default:
    Globals.child_pid = child_pid;
    parent_process();
  }
}

void check_admin() {
  uid_t ruid, euid, suid;
  getresuid(&ruid, &euid, &suid);
  // printf("ruid = %d, euid = %d, suid = %d\n", ruid, euid, suid);
  if (euid != 0) {
    fatal(2, "You must be root to run 'carcer'");
  }
}

void init_config() {
  Config.exe_path = NULL;
  Config.input_file = NULL;
  Config.output_file = NULL;
  Config.error_file = NULL;
  Config.uid = -1;
  Config.gid = -1;
  Config.max_real_time_ms = 1000;
  Config.max_cpu_s = 1;
  Config.max_memory_KB = 10 * 1024;
  Config.max_output_size_KB = 10 * 1024;
}

void check_config() {
  if (Config.exe_path == NULL) {
    fatal(1, "Executable file path (<exe_path>) is missing");
  }
}

void show_config() {
  printf("exe_path:           %s\n", Config.exe_path);
  printf("input_file:         %s\n", Config.input_file);
  printf("output_file:        %s\n", Config.output_file);
  printf("error_file:         %s\n", Config.error_file);
  printf("uid:                %d\n", Config.uid);
  printf("gid:                %d\n", Config.gid);
  printf("max_real_time_ms:   %d\n", Config.max_real_time_ms);
  printf("max_cpu_s:          %d\n", Config.max_cpu_s);
  printf("max_memory:         %d\n", Config.max_memory_KB);
  printf("max_output_size_KB: %d\n", Config.max_output_size_KB);
}

void show_report() {
  static const char *JSON_template =
      "{                                                \n"
      "  \"cpu_time\": %d,\n"
      "  \"real_time\": %d,\n"
      "  \"memory\": %ld,\n"
      "  \"exit_code\": %d,\n"
      "  \"report\": \"%s\""
      "}                                                \n";

  printf(JSON_template, Results.cpu_time_ms, Results.real_time_ms,
         Results.memory, Results.exit_code, report_message[Results.report]);
}

int main(int argc, const char *const argv[]) {
  check_admin();

  init_config();
  parse_args(argc, argv);
  check_config();

  do_fork();

  show_report();
}

// TODO: logging