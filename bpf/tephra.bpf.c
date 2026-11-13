// SPDX-License-Identifier: GPL-2.0
/* All programs are compiled as one object so that they share the maps in
 * common.h. Each file below holds the programs of one area. */
#include "exec.bpf.c"
#include "file.bpf.c"
#include "net.bpf.c"
#include "priv.bpf.c"
#include "tamper.bpf.c"
#include "enforce.bpf.c"
