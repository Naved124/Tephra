#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
python3 -c "import ctypes; ctypes.CDLL(None).syscall(176, b'dummy', 0)"
