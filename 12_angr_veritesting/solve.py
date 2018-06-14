#!/usr/bin/env python

import angr
import claripy
from pwn import *

def find_success(state):
	stdout = state.posix.dumps(1)
	return 'Good' in stdout

proj = angr.Project('./angr_veritesting')
state = proj.factory.entry_state()

simgr = proj.factory.simgr(state, veritesting=True)

simgr.explore(find=find_success)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	print found.posix.dumps(0)[:32]
