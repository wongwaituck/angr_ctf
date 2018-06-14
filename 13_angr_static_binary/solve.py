#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x080489dc 
avoid = 0x080489ca 
#def find_success(state):
#	stdout = state.posix.dumps(1)
#	return 'Good' in stdout

proj = angr.Project('./angr_static')
state = proj.factory.entry_state()

e = ELF('./angr_static')
proj.hook(e.symbols['printf'], angr.SIM_PROCEDURES['libc']['printf']())
proj.hook(e.symbols['__isoc99_scanf'], angr.SIM_PROCEDURES['libc']['scanf']())
proj.hook(e.symbols['puts'], angr.SIM_PROCEDURES['libc']['puts']())
proj.hook(e.symbols['__libc_start_main'], angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

simgr = proj.factory.simgr(state)

simgr.explore(find=find)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	print found.posix.dumps(0)[:8]
