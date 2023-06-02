
```
usage: carcer [<opts>...] <exe_path>

  Execute a binary with seccomp syscall filters.

Options:
  -i, --stdin <file>  File to use as stdin
  -o, --stdout <file> File to use as stdout
  -e, --stder <file>  File to use as stderr
  -u, --uid <n>       Run as user ID <n>
  -g, --gid <n>       Run as group ID <n>
  -m, --mem <m>       Limit memory to <m> in KBs       [default = 100]
  -c, --cpu <c>       Limit CPU time to <c> in seconds [default = 5]
  -r, --real <r>      Limit real time to <r> in ms     [default = 5000]
  -s, --out-size <o>  Limit output size to <o> in KBs  [default = 10]

```
