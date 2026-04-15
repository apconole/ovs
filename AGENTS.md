# AGENTS.md - Open vSwitch Userspace Code Review Guidelines for AI Tools

## CRITICAL INSTRUCTION - READ FIRST

This document has two categories of review rules with different
confidence thresholds:

### 1. Correctness Bugs -- HIGHEST PRIORITY (report at >=50% confidence)

**Always report potential correctness bugs.** These are the most
valuable findings. When in doubt, report them with a note about
your confidence level. A possible use-after-free or resource leak
is worth mentioning even if you are not certain.

Correctness bugs include:
- Calling `ds_init` multiple times on a single variable.
- Use-after-free (accessing memory after `free`/`ds_destroy`/`ds_steal_cstr`)
- Resource leaks on error paths (memory, file descriptors, locks)
- Double-free or double-close
- NULL pointer dereference
- Buffer overflows or out-of-bounds access
- Uninitialized variable use in a reachable code path
- Race conditions (unsynchronized shared state)
- `volatile` used instead of atomic operations for inter-thread shared variables
- Missing error checks on functions that can fail
- Error paths that skip cleanup (goto labels, missing free/close)
- Incorrect error propagation (wrong return value, lost errno)
- Logic errors in conditionals (wrong operator, inverted test)
- Integer overflow/truncation in size calculations
- Missing bounds checks on user-supplied sizes or indices
- `mmap()` return checked against `NULL` instead of `MAP_FAILED`
- Statistics accumulation using `=` instead of `+=`
- Integer multiply without widening cast losing upper bits (16×16, 32×32, etc.)
- Passing unsanitized data to processing functions
- Unbounded descriptor chain traversal on guest/API-supplied data
- `1 << n` on 64-bit bitmask
- Left shift of narrow unsigned (`uint8_t`/`uint16_t`) used as 64-bit value (sign extension via implicit `int` promotion)
- Variable assigned then overwritten before being read (dead store)
- Same variable used as loop counter in nested loops
- `memcpy`/`memcmp`/`memset` with same pointer for source and destination (no-op or undefined)
- Hardcoded Ethernet overhead instead of per-device calculation
- Flow structure updates that violate the constraints of the classifier's subtable structure.

**Do NOT self-censor correctness bugs.** If you identify a code
path where a resource could leak or memory could be used after
free, report it. Do not talk yourself out of it.

### 2. Style, Process, and Formatting -- suppress false positives

**NEVER list a style/process item under "Errors" or "Warnings" if
you conclude it is correct.**

Before outputting any style, formatting, or process error/warning,
verify it is actually wrong. If your analysis concludes with
phrases like "there's no issue here", "which is fine", "appears
correct", "is acceptable", or "this is actually correct" -- then
DO NOT INCLUDE IT IN YOUR OUTPUT AT ALL. Delete it. Omit it
entirely.

This suppression rule applies to: naming conventions,
code style, and process compliance. It does NOT apply to
correctness bugs listed above. (Things like spelling mistakes and
commit message formatting are handled by checkpatch and are
excluded from AI review entirely.)

---

This document provides guidelines for AI-powered code review tools
when reviewing contributions to the Open vSwitch Userspace code. 
It is derived from the official OVS contributor guidelines
and validation scripts.

## Overview

OVS follows a development process modeled on the Linux Kernel. All
patches are reviewed publicly on the mailing list before being
merged. AI review tools should verify compliance with the standards
outlined below.

## Review Philosophy

**Correctness bugs are the primary goal of AI review.** Style and
formatting checks are secondary. A review that catches a
use-after-free but misses a style nit is far more valuable than
one that catches every style issue but misses the bug.

**BEFORE OUTPUTTING YOUR REVIEW**: Re-read each item.
- For correctness bugs: keep them. If you have reasonable doubt
  that a code path is safe, report it.
- For style/process items: if ANY item contains phrases like "is
  fine", "no issue", "appears correct", "is acceptable",
  "actually correct" -- DELETE THAT ITEM. Do not include it.

### Correctness review guidelines
- Trace error paths: for every function that allocates a resource
  or acquires a lock, verify that ALL error paths after that point
  release it
- Check every `goto error` and early `return`: does it clean up
  everything allocated so far?
- Look for use-after-free: after `free(p)`, is `p` accessed again?
- Check that error codes are propagated, not silently dropped
- Report at >=50% confidence; note uncertainty if appropriate
- It is better to report a potential bug that turns out to be safe
  than to miss a real bug

### Style and process review guidelines
- Only comment on style/process issues when you have HIGH CONFIDENCE (>80%) that an issue exists
- Be concise: one sentence per comment when possible
- Focus on actionable feedback, not observations
- When reviewing text, only comment on clarity issues if the text is genuinely
  confusing or could lead to errors.
- Do NOT comment on copyright years, SPDX format, or copyright holders - not subject to AI review
- Do NOT report an issue then contradict yourself - if something is acceptable, do not mention it at all
- Do NOT include items in Errors/Warnings that you then say are "acceptable" or "correct"
- Do NOT mention things that are correct or "not an issue" - only report actual problems
- Do NOT speculate about contributor circumstances (employment, company policies, etc.)
- Before adding any style item to your review, ask: "Is this actually wrong?" If no, omit it entirely.
- NEVER write "(Correction: ...)" - if you need to correct yourself, simply omit the item entirely
- Do NOT add vague suggestions like "should be verified" or "should be checked" - either it's wrong or don't mention it
- Do NOT flag something as an Error then say "which is correct" in the same item
- Do NOT say "no issue here" or "this is actually correct" - if there's no issue, do not include it in your review
- Do NOT analyze cross-patch dependencies or compilation order - you cannot reliably determine this from patch review
- Do NOT claim a patch "would cause compilation failure" based on symbols used in other patches in the series
- Review each patch individually for its own correctness; assume the patch author ordered them correctly
- When reviewing a patch series, OMIT patches that have no issues. Do not include a patch in your output just to say "no issues found" or to summarize what the patch does. Only include patches where you have actual findings to report.

## Priority Areas (Review These)

### Security & Safety
- Unsafe code blocks without justification
- Command injection risks (shell commands, user input)
- Path traversal vulnerabilities
- Credential exposure or hard coded secrets
- Missing input validation on external data
- Improper error handling that could leak sensitive info

### Correctness Issues
- Logic errors that could cause panics or incorrect behavior
- Buffer overflows
- Race conditions
- **`volatile` for inter-thread synchronization**: `volatile` does not
  provide atomicity or memory ordering between threads.
- Resource leaks (files, connections, memory)
- Off-by-one errors or boundary conditions
- Incorrect error propagation
- **Use-after-free** (any access to memory after it has been freed)
- **Error path resource leaks**: For every allocation or fd open,
  trace each error path (`goto`, early `return`, conditional) to
  verify the resource is released. Common patterns to check:
  - `malloc` followed by a failure that does `return -1`
    instead of `goto cleanup`.  `xalloc` family always succed or abort.
  - `open()`/`socket()` fd not closed on a later error
  - Lock acquired but not released on an error branch
  - Partially initialized structure where early fields are allocated
    but later allocation fails without freeing the early ones
- **Double-free / double-close**: resource freed in both a normal
  path and an error path, or fd closed but not set to -1 allowing
  a second close
- **Missing error checks**: functions that can fail (malloc, open,
  ioctl, etc.) whose return value is not checked
- **Do NOT flag unchecked return values from functions that always
  succeed on Linux.** Some POSIX functions are documented to always
  return zero on Linux when called with valid arguments. Flagging
  unchecked returns from these is a false positive. The list includes:
  - `pthread_mutex_init()`, `pthread_cond_init()`
  - `pthread_cond_signal()`, `pthread_cond_broadcast()`,
    `pthread_cond_wait()`
  - `pthread_condattr_init()`, `pthread_condattr_destroy()`
  - `pthread_attr_init()`, `pthread_attr_destroy()`
- Changes to API without release notes
- Changes to ABI on non-LTS release
- Usage of deprecated APIs when replacements exist
- Overly defensive code that adds unnecessary checks
- Unnecessary comments that just restate what the code already shows (remove them)
- **Process-shared synchronization errors** (pthread mutexes in shared memory without `PTHREAD_PROCESS_SHARED`)
- **`mmap()` checked against NULL instead of `MAP_FAILED`**: `mmap()` returns
  `MAP_FAILED` (i.e., `(void *)-1`) on failure, NOT `NULL`. Checking
  `== NULL` or `!= NULL` will miss the error and use an invalid pointer.
  ```c
  /* BAD - mmap never returns NULL on failure */
  p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  if (p == NULL)       /* WRONG - will not catch MAP_FAILED */
      return -1;

  /* GOOD */
  p = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED)
      return -1;
  ```
- **Statistics accumulation using `=` instead of `+=`**: When accumulating
  statistics (counters, byte totals, packet counts), using `=` overwrites
  the running total with only the latest value. This silently produces
  wrong results.
  ```c
  /* BAD - overwrites instead of accumulating */
  stats->rx_packets = nb_rx;
  stats->rx_bytes = total_bytes;

  /* GOOD - accumulates over time */
  stats->rx_packets += nb_rx;
  stats->rx_bytes += total_bytes;
  ```
  Note: `=` is correct for gauge-type values (e.g., queue depth, link
  status) and for initial assignment. Only flag when the context is
  clearly incremental accumulation (loop bodies, per-burst counters,
  callback tallies).
- **Integer multiply without widening cast**: When multiplying integers
  to produce a result wider than the operands (sizes, offsets, byte
  counts), the multiplication is performed at the operand width and
  the upper bits are silently lost before the assignment. This applies
  to any narrowing scenario: 16×16 assigned to a 32-bit variable,
  32×32 assigned to a 64-bit variable, etc.
  ```c
  /* BAD - 32×32 overflows before widening to 64 */
  uint64_t total_size = num_entries * entry_size;  /* both are uint32_t */
  size_t offset = ring->idx * ring->desc_size;     /* 32×32 → truncated */

  /* BAD - 16×16 overflows before widening to 32 */
  uint32_t byte_count = pkt_len * nb_segs;         /* both are uint16_t */

  /* GOOD - widen before multiply */
  uint64_t total_size = (uint64_t)num_entries * entry_size;
  size_t offset = (size_t)ring->idx * ring->desc_size;
  uint32_t byte_count = (uint32_t)pkt_len * nb_segs;
  ```
- **Unbounded descriptor chain traversal**: When walking a chain of
  descriptors (virtio, DMA, NIC Rx/Tx rings) where the chain length
  or next-index comes from guest memory or an untrusted API caller,
  the traversal MUST have a bounds check or loop counter to prevent
  infinite loops or out-of-bounds access from malicious/corrupt data.
  ```c
  /* BAD - guest controls desc[idx].next with no bound */
  while (desc[idx].flags & VRING_DESC_F_NEXT) {
      idx = desc[idx].next;          /* guest-supplied, unbounded */
      process(desc[idx]);
  }

  /* GOOD - cap iterations to descriptor ring size */
  for (i = 0; i < ring_size; i++) {
      if (!(desc[idx].flags & VRING_DESC_F_NEXT))
          break;
      idx = desc[idx].next;
      if (idx >= ring_size)          /* bounds check */
          return -EINVAL;
      process(desc[idx]);
  }
  ```
  This applies to any chain/linked-list traversal where indices or
  pointers originate from untrusted input (guest VMs, user-space
  callers, network packets).
- **Bitmask shift using `1` instead of `1ULL` on 64-bit masks**: The
  literal `1` is `int` (32 bits). Shifting it by 32 or more is
  undefined behavior; shifting it by less than 32 but assigning to a
  `uint64_t` silently zeroes the upper 32 bits. Use `1ULL << n`,
  or `UINT64_C(1) << n`.
  ```c
  /* BAD - 1 is int, UB if n >= 32, wrong if result used as uint64_t */
  uint64_t mask = 1 << bit_pos;
  if (features & (1 << BIT_POS_S))  /* bit 15 OK, bit 32+ UB */

  /* GOOD */
  uint64_t mask = UINT64_C(1) << bit_pos;
  uint64_t mask = 1ULL << bit_pos;
  uint64_t mask = RTE_BIT64(bit_pos);        /* preferred in DPDK */
  if (features & RTE_BIT64(VIRTIO_NET_F_MRG_RXBUF))
  ```
  Note: `1U << n` is acceptable when the mask is known to be 32-bit
  (e.g., `uint32_t` register fields with `n < 32`). Only flag when
  the result is stored in, compared against, or returned as a 64-bit
  type, or when `n` could be >= 32.
- **Left shift of narrow unsigned type sign-extends to 64-bit**: When
  a `uint8_t` or `uint16_t` value is left-shifted, C integer promotion
  converts it to `int` (signed 32-bit) before the shift. If the result
  has bit 31 set, implicit conversion to `uint64_t`, `size_t`, or use
  in pointer arithmetic sign-extends the upper 32 bits to all-1s,
  producing a wrong address or value. This is Coverity SIGN_EXTENSION.
  The fix is to cast the narrow operand to an unsigned type at least as
  wide as the target before shifting.
  ```c
  /* BAD - uint16_t promotes to signed int, bit 31 may set,
   * then sign-extends when converted to 64-bit for pointer math */
  uint16_t idx = get_index();
  void *addr = base + (idx << wqebb_shift);      /* SIGN_EXTENSION */
  uint64_t off = (uint64_t)(idx << shift);        /* too late: shift already in int */

  /* BAD - uint8_t shift with result used as size_t */
  uint8_t page_order = get_order();
  size_t size = page_order << PAGE_SHIFT;          /* promotes to int first */

  /* GOOD - cast before shift */
  void *addr = base + ((uint64_t)idx << wqebb_shift);
  uint64_t off = (uint64_t)idx << shift;
  size_t size = (size_t)page_order << PAGE_SHIFT;

  /* GOOD - intermediate unsigned variable */
  uint32_t offset = (uint32_t)idx << wqebb_shift;  /* OK if result fits 32 bits */
  ```
  Note: This is distinct from the `1 << n` pattern (where the literal
  `1` is the problem) and from the integer-multiply pattern (where
  the operation is `*` not `<<`). The mechanism is the same C integer
  promotion rule, but the code patterns and Coverity checker names
  differ. Only flag when the shift result is used in a context wider
  than 32 bits (64-bit assignment, pointer arithmetic, function
  argument expecting `uint64_t`/`size_t`). A shift whose result is
  stored in a `uint32_t` or narrower variable is not affected.
- **Variable overwrite before read (dead store)**: A variable is
  assigned a value that is unconditionally overwritten before it is
  ever read. This usually indicates a logic error (wrong variable
  name, missing `if`, copy-paste mistake) or at minimum is dead code.
  ```c
  /* BAD - first assignment is never read */
  ret = validate_input(cfg);
  ret = apply_config(cfg);     /* overwrites without checking first ret */
  if (ret != 0)
      return ret;

  /* GOOD - check each return value */
  ret = validate_input(cfg);
  if (ret != 0)
      return ret;
  ret = apply_config(cfg);
  if (ret != 0)
      return ret;
  ```
  Do NOT flag cases where the initial value is intentionally a default
  that may or may not be overwritten (e.g., `int ret = 0;` followed
  by a conditional assignment). Only flag unconditional overwrites
  where the first value can never be observed.
- **Shared loop counter in nested loops**: Using the same variable as
  the loop counter in both an outer and inner loop causes the outer
  loop to malfunction because the inner loop modifies its counter.
  ```c
  /* BAD - inner loop clobbers outer loop counter */
  int i;
  for (i = 0; i < nb_queues; i++) {
      setup_queue(i);
      for (i = 0; i < nb_descs; i++)    /* BUG: reuses i */
          init_desc(i);
  }

  /* GOOD - distinct loop counters */
  for (int i = 0; i < nb_queues; i++) {
      setup_queue(i);
      for (int j = 0; j < nb_descs; j++)
          init_desc(j);
  }
  ```
- **`memcpy`/`memcmp`/`memset` self-argument (same pointer as both
  operands)**: Passing the same pointer as both source and destination
  to `memcpy()` is undefined behavior per C99. Passing the same
  pointer to both arguments of `memcmp()` is a no-op that always
  returns 0, indicating a logic error (usually a copy-paste mistake
  with the wrong variable name). The same applies to `memmove()` 
  with identical arguments.
  ```c
  /* BAD - memcpy with same src and dst is undefined behavior */
  memcpy(buf, buf, len);

  /* BAD - memcmp with same pointer always returns 0 (logic error) */
  if (memcmp(key, key, KEY_LEN) == 0)  /* always true, wrong variable? */

  /* BAD - likely copy-paste: should be comparing two different MACs */
  if (memcmp(&eth->src_addr, &eth->src_addr, RTE_ETHER_ADDR_LEN) == 0)

  /* GOOD - comparing two different things */
  memcpy(dst, src, len);
  if (memcmp(&eth->src_addr, &eth->dst_addr, RTE_ETHER_ADDR_LEN) == 0)
  ```
  This pattern almost always indicates a copy-paste bug where one of
  the arguments should be a different variable.

### Architecture & Patterns
- Code that violates existing patterns in the code base
- Missing error handling
- Code that is not safe against signals

### New Library API Design

When a patch adds a new library under `lib/`, review API design in
addition to correctness and style.

**Callback structs** (Warning / Error). Any function-pointer struct
in an installed header is an ABI break waiting to happen. Adding or
reordering a member breaks all consumers.
- Prefer a single callback parameter over an ops table.
- \>5 callbacks: **Warning** — likely needs redesign.
- \>20 callbacks: **Error** — this is an app plugin API, not a library.
- All callbacks must have Doxygen (contract, return values, ownership).
- Void-returning callbacks for failable operations swallow errors —
  flag as **Error**.
- Callbacks serving app-specific needs (e.g. `verbose_level_get`)
  indicate wrong code was extracted into the library.

**Extensible structures.** Prefer TLV / tagged-array patterns over
enum + union, following `rte_flow_item` and `rte_flow_action` as
the model. Type tag + pointer to type-specific data allows adding
types without ABI breaks. Flag as **Warning**:
- Large enums (100+) consumers must switch on.
- Unions that grow with every new feature.
- Ask: "What changes when a feature is added next release?" If
  "add an enum value and union arm" — should be TLV.

**Installed headers.** If it's in `headers` or `indirect_headers`
in meson.build, it's public API. Don't call it "private." If truly
internal, don't install it.

**Global state.** Prefer handle-based APIs (`create`/`destroy`)
over singletons. `rte_acl` allows multiple independent classifier
instances; new libraries should do the same.

**Output ownership.** Prefer caller-allocated or library-allocated-
caller-freed over internal static buffers. If static buffers are
used, document lifetime and ensure Doxygen examples don't show
stale-pointer usage.

---

## C Coding Style

### General Formatting

- **No trailing whitespace** on lines or at end of files
- Files must end with a new line
- Code style should be consistent within each file

### Comments

Write comments as full sentences starting with a capital letter and ending
with a period. Put two spaces between sentences.

```c
/* Most single-line comments look like this. */

/*
 * Multi-line comments look like this.  Make them real sentences.  Fill
 * them so they look like real paragraphs.
 */
```

**Never use `//` comments** — OVS style requires `/* */` exclusively.

**Do not comment out code** with `//`, `/* */`, or `#if 0`. Just delete it;
version control preserves history.

Use `XXX` or `FIXME` to mark code that needs work.

Each non-static function, each variable declared outside a function, and each
struct/union/typedef declaration should be preceded by a comment. Simple
static functions do not need a comment.

### Header Guards

OVS header guards use the filename in `ALL_CAPS` with a trailing ` 1`:

```c
#ifndef NETDEV_H
#define NETDEV_H 1

/* ... */

#endif /* netdev.h */
```

Do NOT use the `_FILE_H_` pattern (leading/trailing underscores) — that is a
POSIX-reserved namespace.

### Naming Conventions

- **Functions and variables**: `lowercase_with_underscores` only (no CamelCase)
- **Macros, macro parameters, and enum values**: `ALL_UPPERCASE`
- **Module prefix**: Pick a unique prefix ending with `_` for each module and
  apply it to all externally visible names (e.g. `netdev_`, `ofproto_`).
  Names of macro parameters, struct/union members, and function prototype
  parameters are **not** considered externally visible.
- **Arrays**: Give them plural names.
- **No leading underscores**: Do not begin names with `_`. Use `__` as a
  *suffix* for "internal use only" names.
- **Avoid negative names**: `found` is better than `not_found`.
- **`size` vs `length`**: A buffer has *size* (bytes); a string has *length*
  (characters). String length does not include the null terminator.

### Comparisons and Boolean Logic

```c
/* Pointers - compare explicitly with NULL */
if (p == NULL)      /* Good */
if (p != NULL)      /* Good */
if (likely(p != NULL))   /* Good - likely/unlikely don't change this */
if (unlikely(p == NULL)) /* Good - likely/unlikely don't change this */
if (!p)             /* Bad - don't use ! on pointers */

/* Integers - compare explicitly with zero */
if (a == 0)         /* Good */
if (a != 0)         /* Good */
if (errno != 0)     /* Good - this IS explicit */
if (likely(a != 0)) /* Good - likely/unlikely don't change this */
if (!a)             /* Bad - don't use ! on integers */
if (a)              /* Bad - implicit, should be a != 0 */

/* Characters - compare with character constant */
if (*p == '\0')     /* Good */

/* Booleans - direct test is acceptable */
if (flag)           /* Good for actual bool types */
if (!flag)          /* Good for actual bool types */
```

**Explicit comparison** means using `==` or `!=` operators (e.g., `x != 0`, `p == NULL`).
**Implicit comparison** means relying on truthiness without an operator (e.g., `if (x)`, `if (!p)`).

OVS style: put the expression/variable on the **left** and the constant on
the **right**: write `x == 0`, not `0 == x`.

### Boolean Usage

Prefer `bool` (from `<stdbool.h>`) over `int` for variables,
parameters, and return values that are purely true/false. Using
`bool` makes intent explicit, enables compiler diagnostics for
misuse, and is self-documenting.

```c
/* Bad - int used as boolean flag */
int verbose = 0;
int is_enabled = 1;

int
check_valid(struct item *item)
{
    if (item->flags & ITEM_VALID)
        return 1;
    return 0;
}

/* Good - bool communicates intent */
bool verbose = false;
bool is_enabled = true;

bool
check_valid(struct item *item)
{
    return item->flags & ITEM_VALID;
}
```

**Guidelines:**
- Use `bool` for variables that only hold true/false values
- Use `bool` return type for predicate functions (functions that
  answer a yes/no question, often named `is_*`, `has_*`, `can_*`)
- Use `true`/`false` rather than `1`/`0` for boolean assignments
- Boolean variables and parameters should not use explicit
  comparison: `if (verbose)` is correct, not `if (verbose == true)`
- `int` is still appropriate when a value can be negative, is an
  error code, or carries more than two states

**Structure fields:**
- `bool` occupies 1 byte. In packed or cache-critical structures,
  consider using a bitfield or flags word instead
- For configuration structures and non-hot-path data, `bool` is
  preferred over `int` for flag fields

```c
/* Bad - int flags waste space and obscure intent */
struct port_config {
    int promiscuous;     /* 0 or 1 */
    int link_up;         /* 0 or 1 */
    int autoneg;         /* 0 or 1 */
    uint16_t mtu;
};

/* Good - bool for flag fields */
struct port_config {
    bool promiscuous;
    bool link_up;
    bool autoneg;
    uint16_t mtu;
};

/* Also good - bitfield for cache-critical structures */
struct fast_path_config {
    uint32_t flags;      /* bitmask of CONFIG_F_* */
    /* ... hot-path fields ... */
};
```

**Do NOT flag:**
- `int` return type for functions that return error codes (0 for
  success, negative for error) — these are NOT boolean
- `int` used for tri-state or multi-state values
- `int` flags in existing code where changing the type would be a
  large, unrelated refactor
- Bitfield or flags-word approaches in performance-critical
  structures

### Indentation and Braces

OVS uses **4-space indentation** (no tabs) and **BSD-style brace placement**.

**Enclose single statements in braces** — OVS requires braces even for
one-statement bodies:

```c
/* Good - braces required even for single statement */
if (a > b) {
    return a;
} else {
    return b;
}

/* Bad - missing braces */
if (a > b)
    return a;
```

Switch statements: `case` labels are **not** indented relative to `switch`.
Unreachable default cases should use `OVS_NOT_REACHED()`:

```c
switch (conn->state) {
case S_RECV:
    error = run_connection_input(conn);
    break;
case S_SEND:
    error = run_connection_output(conn);
    break;
default:
    OVS_NOT_REACHED();
}
```

Use `for (;;)` for infinite loops (not `while (1)` or `while (true)`).

### Variable Declarations

- Prefer declaring variables inside the basic block where they are used
- Variables may be declared either at the start of the block, or at point of first use (C99 style)
- Both declaration styles are acceptable; consistency within a function is preferred
- Initialize variables only when a meaningful value exists at declaration time
- Use C99 designated initializers for structures

```c
/* Good - declaration at start of block */
int ret;
ret = some_function();

/* Also good - declaration at point of use (C99 style) */
for (int i = 0; i < count; i++)
    process(i);

/* Good - declaration in inner block where variable is used */
if (condition) {
    int local_val = compute();
    use(local_val);
}

/* Bad - unnecessary initialization defeats compiler warnings */
int ret = 0;
ret = some_function();    /* Compiler won't warn if assignment removed */
```

### Function Format

- Return type, function name, and the braces each on **separate lines**,
  all starting in **column 0**.
- Write a comment before each non-static function definition describing its
  purpose, parameters, return value, and side effects. Reference argument
  names in single quotes: `'arg'`. Do not repeat the function name.

```c
/* Returns the larger of 'a' and 'b'. */
int
max_int(int a, int b)
{
    return a > b ? a : b;
}
```

Functions that **destroy** a dynamically-allocated type must accept and
**ignore a null pointer argument** (like `free()`). Callers should omit a
null-pointer check before calling such functions.

Do not mark `.c` file functions `inline`; it suppresses useful compiler
warnings without reliably helping code generation.

---

## Unnecessary Code Patterns

The following patterns add unnecessary code, hide bugs, or reduce performance. Avoid them.

### Unnecessary Variable Initialization

Do not initialize variables that will be assigned before use. This defeats the compiler's uninitialized variable warnings, hiding potential bugs.

```c
/* Bad - initialization defeats -Wuninitialized */
int ret = 0;
if (condition)
    ret = func_a();
else
    ret = func_b();

/* Good - compiler will warn if any path misses assignment */
int ret;
if (condition)
    ret = func_a();
else
    ret = func_b();

/* Good - meaningful initial value */
int count = 0;
for (i = 0; i < n; i++)
    if (test(i))
        count++;
```

### Unnecessary Casts of void *

In C, `void *` converts implicitly to any pointer type. Casting the result of `malloc()`, `calloc()`, `rte_malloc()`, or similar functions is unnecessary and can hide the error of a missing `#include <stdlib.h>`.

```c
/* Bad - unnecessary cast */
struct foo *p = (struct foo *)malloc(sizeof(*p));
struct bar *q = (struct bar *)rte_malloc(NULL, sizeof(*q), 0);

/* Good - no cast needed in C */
struct foo *p = malloc(sizeof(*p));
struct bar *q = rte_malloc(NULL, sizeof(*q), 0);
```

Note: Casts are required in C++ but DPDK is a C project.

### Zero-Length Arrays vs Variable-Length Arrays

Zero-length arrays (`int arr[0]`) are a GCC extension. Use C99 flexible array members instead.

```c
/* Bad - GCC extension */
struct msg {
    int len;
    char data[0];
};

/* Good - C99 flexible array member */
struct msg {
    int len;
    char data[];
};
```

### Unnecessary NULL Checks Before free()

`free()` and OVS destructor functions accept NULL pointers safely. Do not add
redundant NULL checks. OVS coding style mandates that destructor functions
(e.g. `netdev_close()`, `ds_destroy()`) also accept NULL, so callers should
not guard those calls either.

```c
/* Bad - unnecessary check */
if (ptr != NULL) {
    free(ptr);
}

/* Good - free handles NULL */
free(ptr);
```

### memset Before free() (CWE-14)

Do not call `memset()` to zero memory before freeing it. The compiler may
optimize away the `memset()` as a dead store (CWE-14). For security-sensitive
data, use `explicit_bzero()` which the compiler is not permitted to eliminate.

```c
/* Bad - compiler may eliminate memset */
memset(secret_key, 0, sizeof(secret_key));
free(secret_key);

/* Good - for non-sensitive data, just free */
free(ptr);

/* Good - explicit_bzero cannot be optimized away */
explicit_bzero(secret_key, sizeof(secret_key));
free(secret_key);
```

### Allocation: xmalloc vs malloc

OVS provides `xmalloc()`, `xzalloc()`, `xstrdup()`, and related wrappers in
`lib/util.h`. These abort the process on allocation failure — they **never
return NULL**. Do NOT add NULL checks after `xmalloc()` family calls.

```c
/* Bad - xmalloc never returns NULL */
struct foo *p = xmalloc(sizeof *p);
if (p == NULL) {          /* dead code, and wrong style */
    return -ENOMEM;
}

/* Good - no NULL check needed */
struct foo *p = xmalloc(sizeof *p);

/* Good - sizeof applied to the expression, not the type */
struct foo *p = xmalloc(sizeof *p);
```

Use plain `malloc()` only when you need to handle allocation failure yourself
(e.g. in low-level code that must not abort). Use the `x`-prefixed wrappers
for normal control-path allocations.

### Non-const Function Pointer Arrays

Arrays of function pointers (ops tables, dispatch tables, callback arrays)
should be declared `const` when their contents are fixed at compile time.
A non-`const` function pointer array can be overwritten by bugs or exploits,
and prevents the compiler from placing the table in read-only memory.

```c
/* Bad - mutable when it doesn't need to be */
static rte_rx_burst_t rx_functions[] = {
    rx_burst_scalar,
    rx_burst_vec_avx2,
    rx_burst_vec_avx512,
};

/* Good - immutable dispatch table */
static const rte_rx_burst_t rx_functions[] = {
    rx_burst_scalar,
    rx_burst_vec_avx2,
    rx_burst_vec_avx512,
};
```

**Exceptions** (do NOT flag):
- Arrays modified at runtime for CPU feature detection or capability probing
  (e.g., selecting a burst function based on `rte_cpu_get_flag_enabled()`)
- Arrays containing mutable state (e.g., entries that are linked into lists)
- Arrays populated dynamically via registration APIs
- `dev_ops` or similar structures assigned per-device at init time

Only flag when the array is fully initialized at declaration with constant
values and never modified thereafter.

---

## Forbidden Tokens

### Functions

| Forbidden | Preferred | Notes |
|-----------|-----------|-------|
| `pthread_mutex_t` (bare) | `struct ovs_mutex` | Use OVS wrapper with annotations |
| `pthread_mutex_init()` (bare) | `ovs_mutex_init()` or `OVS_MUTEX_INITIALIZER` | |
| `pthread_mutex_lock/unlock()` (bare) | `ovs_mutex_lock()` / `ovs_mutex_unlock()` | |
| `pthread_rwlock_t` (bare) | `struct ovs_rwlock` | |
| `pthread_create()` | `ovs_thread_create()` | Registers thread for debugging |
| `abort()` | `OVS_NOT_REACHED()` | Marks unreachable code with compiler hint |
| `assert()` | `ovs_assert()` | Logs before aborting |
| Raw `malloc()` in normal paths | `xmalloc()` / `xzalloc()` | Wrappers abort on failure |
| `strdup()` | `xstrdup()` | |
| `strtok()` | `strtok_r()` | Not thread-safe |

### Atomics and Memory Barriers

OVS uses the wrappers in `lib/ovs-atomic.h` which provide a portable C11
atomic interface.

| Forbidden | Preferred |
|-----------|-----------|
| `volatile` for inter-thread shared variables | OVS atomic types (`atomic_int`, etc.) |
| `__sync_xxx()` GCC builtins | `atomic_xxx()` from `lib/ovs-atomic.h` |
| `__atomic_xxx()` GCC builtins | `atomic_xxx()` from `lib/ovs-atomic.h` |

#### Shared Variable Access: volatile vs Atomics

Variables shared between threads or between a thread and a signal handler
**must** use OVS atomic types from `lib/ovs-atomic.h`. The C `volatile`
keyword does NOT provide atomicity or memory ordering guarantees between
threads.

```c
/* BAD - volatile provides no inter-thread ordering */
volatile bool stop_flag;
if (stop_flag)           /* data race */
    return;

/* GOOD - OVS atomic */
atomic_bool stop_flag;
bool val;
atomic_read(&stop_flag, &val);
if (val) {
    return;
}
```

`volatile` remains correct only for memory-mapped I/O registers and
interaction with `setjmp`/`longjmp`. Do NOT flag `volatile` in those
contexts.

#### Memory Ordering in OVS

OVS uses C11-style memory order constants through `lib/ovs-atomic.h`:

| OVS Memory Order | When to Use |
|------------------|-------------|
| `memory_order_relaxed` | Statistics counters where no other data depends on the value. |
| `memory_order_acquire` | Load side of a flag that guards other shared data. |
| `memory_order_release` | Store side of a flag that publishes shared data. |
| `memory_order_seq_cst` | When a globally consistent order across multiple atomics is required. |

Use the weakest ordering that is correct. Stronger ordering constrains
hardware and compiler optimization unnecessarily.

### Threading

| Forbidden | Preferred | Notes |
|-----------|-----------|-------|
| Bare `pthread_create()` | `ovs_thread_create()` | Registers thread for debugging |
| Bare `pthread_join()` | `xpthread_join()` | Aborts on error |
| Bare `pthread_mutex_t` | `struct ovs_mutex` | Provides `where` tracking and annotations |
| Bare `pthread_rwlock_t` | `struct ovs_rwlock` | |
| Bare `pthread_mutex_lock()` | `ovs_mutex_lock()` | |
| Bare `pthread_mutex_unlock()` | `ovs_mutex_unlock()` | |

### OVS Thread Safety Annotations

OVS uses Clang thread-safety annotations from `lib/compiler.h` to let the
compiler verify locking discipline statically. **Always annotate shared
variables and the functions that require a lock to be held.**

Key macros (pass the lock object, not its address):

| Macro | Use |
|-------|-----|
| `OVS_GUARDED_BY(mutex)` | On a variable: protected by `mutex` |
| `OVS_REQUIRES(mutex)` | On a function: caller must hold `mutex` |
| `OVS_ACQUIRES(mutex)` | On a function: acquires `mutex` on return |
| `OVS_RELEASES(mutex)` | On a function: releases `mutex` on return |
| `OVS_REQ_RDLOCK(rwlock)` | On a function: caller must hold read lock |
| `OVS_REQ_WRLOCK(rwlock)` | On a function: caller must hold write lock |
| `OVS_EXCLUDED(mutex)` | On a function: must NOT hold `mutex` |

```c
/* Good - annotations on shared data and functions that access it */
static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static struct hmap all_items OVS_GUARDED_BY(mutex);

static void item_add__(struct item *) OVS_REQUIRES(mutex);
static void item_remove__(struct item *) OVS_REQUIRES(mutex);

void
item_add(struct item *item)
    OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    item_add__(item);
    ovs_mutex_unlock(&mutex);
}
```

Flag as an **Error**:
- A function that accesses a `OVS_GUARDED_BY` variable without holding the
  named lock and without an `OVS_REQUIRES` annotation.
- An unlock function without `OVS_RELEASES`.
- Using bare `pthread_mutex_t` instead of `struct ovs_mutex`.

Flag as a **Warning**:
- Shared mutable state with no locking annotation.
- Lock acquired but no annotation indicating it is released on all paths.

### Format Specifiers

OVS provides its own portable format specifier macros in `lib/util.h`:

| Forbidden | Preferred | Notes |
|-----------|-----------|-------|
| `%zu` | `"%"PRIuSIZE` | Portable `size_t` |
| `%td` | `"%"PRIdPTR` | Portable `ptrdiff_t` |
| `%ju` | `"%"PRIuMAX` | Portable `uintmax_t` |
| `%zx` | `"%"PRIxSIZE` | Hex `size_t` |
| `%hhd` | `%d` | Use `%d` instead |

Use `PRId64`, `PRIu64`, `PRIx64` for 64-bit integers.

### Headers and Build

| Rule | Notes |
|------|-------|
| First non-comment line of every `.c` file must be `#include <config.h>` | |
| Include order: `<config.h>`, own header, system headers (alphabetical), OVS headers (alphabetical) | |
| Use `""` not `<>` for OVS headers | |
| Header files must be self-contained | Include whatever they need |
| Header guards: `#ifndef FOO_H / #define FOO_H 1` (no leading/trailing `_`) | |
| `-DALLOW_EXPERIMENTAL_API` | Not in lib/drivers/app | Build flags |
### Testing

| Rule | Notes |
|------|-------|
| New code should have tests in `tests/` using the OVS AT (autotest) framework | |
| Bug fix patches should add a test that would have caught the bug | |
| Use `make check` before submission | |

### Documentation

| Forbidden | Preferred |
|-----------|-----------|
| `http://...dpdk.org` | `https://...dpdk.org` |
| `//doc.dpdk.org/guides/...` | `:ref:` or `:doc:` Sphinx references |
| `::  file.svg` | `::  file.*` (wildcard extension) |

---

## Deprecated API Usage

New patches must not introduce usage of deprecated APIs, macros, or functions.
Deprecated items are marked with `RTE_DEPRECATED` or documented in the
deprecation notices section of the release notes.

### Rules for New Code

- Do not call functions marked with `RTE_DEPRECATED` or `__rte_deprecated`
- Do not use macros that have been superseded by newer alternatives
- Do not use data structures or enum values marked as deprecated
- Check `doc/guides/rel_notes/deprecation.rst` for planned deprecations
- When a deprecated API has a replacement, use the replacement

### Deprecating APIs

A patch may mark an API as deprecated provided:

- No remaining usages exist in the current DPDK codebase
- The deprecation is documented in the release notes
- A migration path or replacement API is documented
- The `RTE_DEPRECATED` macro is used to generate compiler warnings

```c
/* Marking a function as deprecated */
__rte_deprecated
int
rte_old_function(void);

/* With a message pointing to the replacement */
__rte_deprecated_msg("use rte_new_function() instead")
int
rte_old_function(void);
```

### Common Deprecated Patterns

| Deprecated | Replacement | Notes |
|-----------|-------------|-------|
| `rte_atomic*_t` types | C11 atomics | Use `rte_atomic_xxx()` wrappers |
| `rte_smp_*mb()` barriers | `rte_atomic_thread_fence()` | See Atomics section |
| `pthread_*()` in portable code | `rte_thread_*()` | See Threading section |

When reviewing patches that add new code, flag any usage of deprecated APIs
as requiring change to use the modern replacement.

---

## API Tag Requirements

### `__rte_experimental`

- Must appear **alone on the line** immediately preceding the return type
- Only allowed in **header files** (not `.c` files)

```c
/* Correct */
__rte_experimental
int
rte_new_feature(void);

/* Wrong - not alone on line */
__rte_experimental int rte_new_feature(void);

/* Wrong - in .c file */
```

### `__rte_internal`

- Must appear **alone on the line** immediately preceding the return type
- Only allowed in **header files** (not `.c` files)

```c
/* Correct */
__rte_internal
int
internal_function(void);
```

### Alignment Attributes

`__rte_aligned`, `__rte_cache_aligned`, `__rte_cache_min_aligned` may only be used with `struct` or `union` types:

```c
/* Correct */
struct __rte_cache_aligned my_struct {
    /* ... */
};

/* Wrong */
int __rte_cache_aligned my_variable;
```

### Packed Attributes

- `__rte_packed_begin` must follow `struct`, `union`, or alignment attributes
- `__rte_packed_begin` and `__rte_packed_end` must be used in pairs
- Cannot use `__rte_packed_begin` with `enum`

```c
/* Correct */
struct __rte_packed_begin my_packed_struct {
    /* ... */
} __rte_packed_end;

/* Wrong - with enum */
enum __rte_packed_begin my_enum {
    /* ... */
};
```

---

## Code Quality Requirements

### Compilation

- Each commit must compile independently (for `git bisect`)
- No forward dependencies within a patchset
- Test with multiple targets, compilers, and options
- Use `devtools/test-meson-builds.sh`

**Note for AI reviewers**: You cannot verify compilation order or cross-patch dependencies from patch review alone. Do NOT flag patches claiming they "would fail to compile" based on symbols used in other patches in the series. Assume the patch author has ordered them correctly.

### Testing

- Add tests to `app/test` unit test framework
- New API functions must be used in `/app` test directory
- New device APIs require at least one driver implementation

#### Functional Test Infrastructure

Standalone functional tests should use the `TEST_ASSERT` macros and `unit_test_suite_runner` infrastructure for consistency and proper integration with the DPDK test framework.

```c
#include <rte_test.h>

static int
test_feature_basic(void)
{
    int ret;

    ret = rte_feature_init();
    TEST_ASSERT_SUCCESS(ret, "Failed to initialize feature");

    ret = rte_feature_operation();
    TEST_ASSERT_EQUAL(ret, 0, "Operation returned unexpected value");

    TEST_ASSERT_NOT_NULL(rte_feature_get_ptr(),
        "Feature pointer should not be NULL");

    return TEST_SUCCESS;
}

static struct unit_test_suite feature_testsuite = {
    .suite_name = "feature_autotest",
    .setup = test_feature_setup,
    .teardown = test_feature_teardown,
    .unit_test_cases = {
        TEST_CASE(test_feature_basic),
        TEST_CASE(test_feature_advanced),
        TEST_CASES_END()
    }
};

static int
test_feature(void)
{
    return unit_test_suite_runner(&feature_testsuite);
}

REGISTER_FAST_TEST(feature_autotest, NOHUGE_OK, ASAN_OK, test_feature);
```

The `REGISTER_FAST_TEST` macro parameters are:
- Test name (e.g., `feature_autotest`)
- `NOHUGE_OK` or `HUGEPAGES_REQUIRED` - whether test can run without hugepages
- `ASAN_OK` or `ASAN_FAILS` - whether test is compatible with Address Sanitizer
- Test function name

Common `TEST_ASSERT` macros:
- `TEST_ASSERT(cond, msg, ...)` - Assert condition is true
- `TEST_ASSERT_SUCCESS(val, msg, ...)` - Assert value equals 0
- `TEST_ASSERT_FAIL(val, msg, ...)` - Assert value is non-zero
- `TEST_ASSERT_EQUAL(a, b, msg, ...)` - Assert two values are equal
- `TEST_ASSERT_NOT_EQUAL(a, b, msg, ...)` - Assert two values differ
- `TEST_ASSERT_NULL(val, msg, ...)` - Assert value is NULL
- `TEST_ASSERT_NOT_NULL(val, msg, ...)` - Assert value is not NULL

### Documentation

- Add Doxygen comments for public APIs
- Update release notes in `doc/guides/rel_notes/` for important changes
- Code and documentation must be updated atomically in same patch
- Only update the **current release** notes file
- Documentation must match the code
- PMD features must match the features matrix in `doc/guides/nics/features/`
- Documentation must match device operations (see `doc/guides/nics/features.rst` for the mapping between features, `eth_dev_ops`, and related APIs)
- Release notes are NOT required for:
  - Test-only changes (unit tests, functional tests)
  - Internal APIs and helper functions (not exported to applications)
  - Internal implementation changes that don't affect public API

### RST Documentation Style

When reviewing `.rst` documentation files, prefer **definition lists**
over simple bullet lists where each item has a term and a description.
Definition lists produce better-structured HTML/PDF output and are
easier to scan.

**When to suggest a definition list:**
- A bullet list where each item starts with a bold or emphasized term
  followed by a dash, colon, or long explanation
- Lists of options, parameters, configuration values, or features
  where each entry has a name and a description
- Glossary-style enumerations

**When a simple list is fine (do NOT flag):**
- Short lists of items without descriptions (e.g., file names, steps)
- Lists where items are single phrases or sentences with no term/definition structure
- Enumerated steps in a procedure

**RST definition list syntax:**

```rst
term 1
   Description of term 1.

term 2
   Description of term 2.
   Can span multiple lines.
```

**Example — flag this pattern:**

```rst
* **error** - Fail with error (default)
* **truncate** - Truncate content to fit token limit
* **summary** - Request high-level summary review
```

**Suggest rewriting as:**

```rst
error
   Fail with error (default).

truncate
   Truncate content to fit token limit.

summary
   Request high-level summary review.
```

This is a **Warning**-level suggestion, not an Error. Do not flag it
when the existing list structure is appropriate (see "when a simple
list is fine" above).

### API and Driver Changes

- New APIs must be marked as `__rte_experimental`
- New APIs must have hooks in `app/testpmd` and tests in the functional test suite
- Changes to existing APIs require release notes
- New drivers or subsystems must have release notes
- Internal APIs (used only within DPDK, not exported to applications) do NOT require release notes

### ABI Compatibility and Symbol Exports

**IMPORTANT**: DPDK uses automatic symbol map generation. Do **NOT** recommend
manually editing `version.map` files - they are auto-generated from source code
annotations.

#### Symbol Export Macros

New public functions must be annotated with export macros (defined in
`rte_export.h`). Place the macro on the line immediately before the function
definition in the `.c` file:

```c
/* For stable ABI symbols */
RTE_EXPORT_SYMBOL(rte_foo_create)
int
rte_foo_create(struct rte_foo_config *config)
{
    /* ... */
}

/* For experimental symbols (include version when first added) */
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_foo_new_feature, 25.03)
__rte_experimental
int
rte_foo_new_feature(void)
{
    /* ... */
}

/* For internal symbols (shared between DPDK components only) */
RTE_EXPORT_INTERNAL_SYMBOL(rte_foo_internal_helper)
int
rte_foo_internal_helper(void)
{
    /* ... */
}
```

#### Symbol Export Rules

- `RTE_EXPORT_SYMBOL` - Use for stable ABI functions
- `RTE_EXPORT_EXPERIMENTAL_SYMBOL(name, ver)` - Use for new experimental APIs
  (version is the DPDK release, e.g., `25.03`)
- `RTE_EXPORT_INTERNAL_SYMBOL` - Use for functions shared between DPDK libs/drivers
  but not part of public API
- Export macros go in `.c` files, not headers
- The build system generates linker version maps automatically

#### What NOT to Review

- Do **NOT** flag missing `version.map` updates - maps are auto-generated
- Do **NOT** suggest adding symbols to `lib/*/version.map` files

#### ABI Versioning for Changed Functions

When changing the signature of an existing stable function, use versioning macros
from `rte_function_versioning.h`:

- `RTE_VERSION_SYMBOL` - Create versioned symbol for backward compatibility
- `RTE_DEFAULT_SYMBOL` - Mark the new default version

Follow ABI policy and versioning guidelines in the contributor documentation.
Enable ABI checks with `DPDK_ABI_REF_VERSION` environment variable.

---

## LTS (Long Term Stable) Release Review

LTS releases are DPDK versions ending in `.11` (e.g., 23.11, 22.11,
21.11, 20.11, 19.11). When reviewing patches targeting an LTS branch,
apply stricter criteria:

### LTS-Specific Rules

- **Only bug fixes allowed** -- no new features
- **No new APIs** (experimental or stable)
- **ABI must remain unchanged** -- no symbol additions, removals,
  or signature changes
- Backported fixes should reference the original commit with a
  `Fixes:` tag
- Copyright years should reflect when the code was originally
  written
- Be conservative: reject changes that are not clearly bug fixes

### What to Flag on LTS Branches

**Error:**
- New feature code (new functions, new driver capabilities)
- New experimental or stable API additions
- ABI changes (new or removed symbols, changed function signatures)
- Changes that add new configuration options or parameters

**Warning:**
- Large refactoring that goes beyond what is needed for a fix
- Missing `Fixes:` tag on a backported bug fix
- Missing `Cc: stable@dpdk.org`

### When LTS Rules Apply

LTS rules apply when the reviewer is told the target release is an
LTS version (via the `--release` option or equivalent). If no
release is specified, assume the patch targets the main development
branch where new features and APIs are allowed.

---

## Dynamic Strings (`struct ds`)

Dynamic strings in OVS use `struct ds` from
`include/openvswitch/dynamic-string.h`. The type manages a heap-allocated,
null-terminated character buffer that grows on demand.

### Lifecycle Rules

**Initialise exactly once** before any use. Either use the static initializer
at declaration time:

```c
/* Good — zero-cost static init; no cleanup needed until something is written */
struct ds s = DS_EMPTY_INITIALIZER;
```

or call `ds_init()` explicitly when declaration and first use are separate:

```c
/* Good — ds_init() called exactly once */
struct ds msg;
ds_init(&msg);
ds_put_cstr(&msg, "hello");
```

**Never call `ds_init()` on a `struct ds` that already holds content.**
Doing so discards the `string` pointer without freeing it, leaking memory:

```c
/* BAD — second ds_init() leaks the first allocation */
struct ds s = DS_EMPTY_INITIALIZER;
ds_put_cstr(&s, "first");
ds_init(&s);                    /* BUG: leaks "first"'s heap memory */
ds_put_cstr(&s, "second");
ds_destroy(&s);

/* Good — use ds_clear() to reset content without freeing */
struct ds s = DS_EMPTY_INITIALIZER;
ds_put_cstr(&s, "first");
ds_clear(&s);                   /* length reset to 0, allocation kept */
ds_put_cstr(&s, "second");
ds_destroy(&s);
```

### Every Init Must Be Paired with a Release

Every `ds_init()` call and every `DS_EMPTY_INITIALIZER` declaration that may
cause allocation must be paired with exactly one of:

- `ds_destroy(&s)` — frees the buffer; leaves `s` in an uninitialised state.
- `ds_steal_cstr(&s)` — returns a `char *` the caller must `free()`, and
  resets `s` to empty (no subsequent `ds_destroy()` is needed or correct).

```c
/* Good — ds_destroy() on every exit path (from lib/bfd.c pattern) */
struct ds s = DS_EMPTY_INITIALIZER;
ds_put_format(&s, "value=%d", val);
if (error) {
    ds_destroy(&s);             /* release before early return */
    return;
}
log_msg(ds_cstr(&s));
ds_destroy(&s);

/* Good — ds_steal_cstr() transfers ownership; no ds_destroy() needed
 * (from lib/unicode.c) */
struct ds msg;
ds_init(&msg);
ds_put_cstr(&msg, "invalid UTF-8 sequence");
return ds_steal_cstr(&msg);    /* caller must free() the returned string */
```

### Error Paths Must Not Skip `ds_destroy()`

Treat `struct ds` like any other heap resource. Trace every `goto`, early
`return`, and error branch to verify that every initialised dynamic string
is released.

```c
/* BAD — ds_destroy() missing on the error path */
struct ds s = DS_EMPTY_INITIALIZER;
ds_put_format(&s, "port %d", port_no);
if (do_something() != 0) {
    return -1;                  /* BUG: s.string is leaked */
}
log_msg(ds_cstr(&s));
ds_destroy(&s);
return 0;

/* Good */
struct ds s = DS_EMPTY_INITIALIZER;
ds_put_format(&s, "port %d", port_no);
if (do_something() != 0) {
    ds_destroy(&s);
    return -1;
}
log_msg(ds_cstr(&s));
ds_destroy(&s);
return 0;
```

### Do Not Access `ds->string` Directly When the String May Be Empty

`struct ds` initially has `string == NULL`. Use `ds_cstr()`, which allocates
and null-terminates on demand, instead of reading `ds->string` directly
whenever there is a chance the buffer has not yet been written to.

```c
/* BAD — ds.string is NULL when nothing has been written */
struct ds s = DS_EMPTY_INITIALIZER;
printf("%s\n", s.string);      /* BUG: NULL dereference */

/* Good */
struct ds s = DS_EMPTY_INITIALIZER;
printf("%s\n", ds_cstr(&s));   /* always returns a valid C string */
ds_destroy(&s);
```

### Severity

Flag as an **Error**:
- `ds_init()` called on a `struct ds` that already holds content — memory
  leak of the existing allocation.
- Any control-flow path (early `return`, `goto`, exception-like jump) that
  bypasses `ds_destroy()` or `ds_steal_cstr()` on an initialised `struct ds`
  — resource leak.
- Direct access to `ds->string` when the string may still be `NULL`.

Flag as a **Warning**:
- The `char *` returned by `ds_steal_cstr()` is stored in a variable that is
  not `free()`d on all exit paths.

---

## Patch Validation Checklist

### Commit Message and License

Checked by `utilities/checkpatch.py` -- not duplicated here.

### Code Style

- [ ] Proper include order
- [ ] Header guards present
- [ ] Proper brace style
- [ ] Function return type on own line
- [ ] No forbidden tokens (see table above)
- [ ] No unnecessary code patterns (see section above)
- [ ] No usage of deprecated APIs, macros, or functions
- [ ] `mmap()` return checked against `MAP_FAILED`, not `NULL`
- [ ] Statistics use `+=` not `=` for accumulation
- [ ] Integer multiplies widened before operation when result is 64-bit
- [ ] Descriptor chain traversals bounded by ring size or loop counter
- [ ] 64-bit bitmasks use `1ULL <<` not `1 <<`
- [ ] Left shifts of `uint8_t`/`uint16_t` cast to unsigned target width before shift when result is 64-bit
- [ ] No unconditional variable overwrites before read
- [ ] Nested loops use distinct counter variables
- [ ] No `memcpy`/`memcmp` with identical source and destination pointers
- [ ] Static function pointer arrays declared `const` when contents are compile-time fixed
- [ ] `bool` used for pure true/false variables, parameters, and predicate return types
- [ ] Memory ordering is the weakest correct choice (`relaxed` for counters, `acquire`/`release` for publish/consume)

### API Tags

- [ ] Alignment attributes only on struct/union
- [ ] Packed attributes properly paired

### Structure

- [ ] Each commit compiles independently
- [ ] Code and docs updated together
- [ ] Documentation matches code behavior
- [ ] Docs use definition lists for term/description patterns
- [ ] Tests added/updated as needed
- [ ] Current NEWS updated for significant changes
- [ ] NEWS updated for API/ABI changes
- [ ] NEWS updated for new user-visible subsystems

---

## Meson Build Files

### Style Requirements

- 4-space indentation (no tabs)
- Line continuations double-indented
- Lists alphabetically ordered
- Short lists (<=3 items): single line, no trailing comma
- Long lists: one item per line, trailing comma on last item
- No strict line length limit for meson files; lines under 100 characters are acceptable

```python
# Short list
sources = files('file1.c', 'file2.c')

# Long list
headers = files(
    'header1.h',
    'header2.h',
    'header3.h',
)
```

---

## Python Code

- Must comply with formatting standards
- Use **`black`** for code formatting validation
- Line length acceptable up to 100 characters

---

## Validation Tools

Run these before submitting:

```bash
```

---

## Severity Levels for AI Review

**Error** (must fix):

*Correctness bugs (highest value findings):*
- Use-after-free
- Resource leaks on error paths (memory, file descriptors, locks)
- Double-free or double-close
- NULL pointer dereference on reachable code path
- Buffer overflow or out-of-bounds access
- Missing error check on a function that can fail, leading to undefined behavior
- Race condition on shared mutable state without synchronization
- `volatile` used instead of atomics for inter-thread shared variables
- Error path that skips necessary cleanup
- `mmap()` return value checked against NULL instead of `MAP_FAILED`
- Statistics accumulation using `=` instead of `+=` (overwrite vs increment)
- Integer multiply without widening cast losing upper bits (16×16, 32×32, etc.)
- Unbounded descriptor chain traversal on guest/API-supplied indices
- `1 << n` used for 64-bit bitmask (undefined behavior if n >= 32)
- Left shift of `uint8_t`/`uint16_t` used in 64-bit context without widening cast (sign extension)
- Variable assigned then unconditionally overwritten before read
- Same variable used as counter in nested loops
- `memcpy`/`memcmp` with same pointer as both arguments (UB or no-op logic error)

*Process and format errors:*
- ABI breaks without proper versioning

*API design errors (new libraries only):*
- Ops/callback struct with 20+ function pointers in an installed header
- Callback struct members with no Doxygen documentation
- Void-returning callbacks for failable operations (errors silently swallowed)

**Warning** (should fix):
- Documentation gaps
- Documentation does not match code behavior
- Missing tests
- Functional tests not using TEST_ASSERT macros or unit_test_suite_runner
- New subsystems without NEWS or documentation
- Unnecessary variable initialization
- Unnecessary casts of `void *`
- Unnecessary NULL checks before free
- Inappropriate use of `xalloc()` or `memcpy()`
- Use of `perror()`, `printf()`, `fprintf()` in libraries (allowed in test code)
- Driver/library global variables without unique prefixes (static linking clash risk)
- Usage of deprecated APIs, macros, or functions in new code
- RST documentation using bullet lists where definition lists would be more appropriate
- Ops/callback struct with >5 function pointers in an installed header (ABI risk)
- New API using fixed enum+union where TLV pattern would be more extensible
- Installed header labeled "private" or "internal" in meson.build
- Static function pointer array not declared `const` when contents are compile-time constant
- `int` used instead of `bool` for variables or return values that are purely true/false
- Hardcoded Ethernet overhead constant instead of per-device overhead calculation

**Do NOT flag** (common false positives):
- Copyright format, copyright years, copyright holders (not subject to AI review)
- Commit message formatting (subject length, punctuation, tag order, case-sensitive terms) -- checked by checkpatch
- Anything you determine is correct (do not mention non-issues or say "No issue here")
- Missing NEWS for test-only changes (unit tests do not require release notes)
- Missing NEWS for internal APIs or helper functions (only public APIs need release notes)
- Any item you later correct with "(Correction: ...)" or "actually acceptable" - just omit it
- Vague concerns ("should be verified", "should be checked") - if you're not sure it's wrong, don't flag it
- Items where you say "which is correct" or "this is correct" - if it's correct, don't mention it at all
- Items where you conclude "no issue here" or "this is actually correct" - omit these entirely
- Clean patches in a series - do not include a patch just to say "no issues" or describe what it does
- Cross-patch compilation dependencies - you cannot determine patch ordering correctness from review
- Claims that a symbol "was removed in patch N" causing issues in patch M - assume author ordered correctly
- Any speculation about whether patches will compile when applied in sequence
- Left shift of `uint8_t`/`uint16_t` where the result is stored in a `uint32_t` or narrower variable and not used in pointer arithmetic or 64-bit context (sign extension cannot occur)

**Info** (consider):
- Minor style preferences
- Optimization suggestions
- Alternative approaches

---

# Response Format

When you identify an issue:
1. **State the problem** (1 sentence)
2. **Why it matters** (1 sentence, only if not obvious)
3. **Suggested fix** (code snippet or specific action)

Example:
This could panic if the string is NULL.

---

## FINAL CHECK BEFORE SUBMITTING REVIEW

Before outputting your review, do two separate passes:

### Pass 1: Verify correctness bugs are included

Ask: "Did I trace every error path for resource leaks? Did I check
for use-after-free? Did I verify error codes are propagated?"

If you identified a potential correctness bug but talked yourself
out of it, **add it back**. It is better to report a possible bug
than to miss a real one.

### Pass 2: Remove style/process false positives

For EACH style/process item, ask: "Did I conclude this is actually
fine/correct/acceptable/no issue?"

If YES, DELETE THAT ITEM. It should not be in your output.

An item that says "X is wrong... actually this is correct" is a
FALSE POSITIVE and must be removed. This applies to style, format,
and process items only.

**If your Errors section would be empty after this check, that's
fine -- it means the patches are good.**
