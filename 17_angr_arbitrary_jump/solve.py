#!/usr/bin/env python

import angr
import claripy
from pwn import *

def check_eip(state):
	eip = state.memory.load(state.regs.esp, 4, endness=state.arch.memory_endness)
	if state.se.symbolic(eip):
		good_addr = 0x4b524f59
		#good_addr = 0x594f524b
		copied_state = state.copy()
		constraint = eip == good_addr
		copied_state.add_constraints(constraint)
		if copied_state.satisfiable():
			state.add_constraints(constraint)
			return True
		else:
			return False

def lol(state):
	if state.addr == 0x4b524f95:
		return check_eip(state)
	else:
		return False

proj = angr.Project('./angr_arb_jump')
state = proj.factory.entry_state()

simgr = proj.factory.simgr(state, save_unconstrained=True)

simgr.explore(find=lol)

for found in simgr.found:
	print 'found'
	print found.posix.dumps(0)

for state in simgr.unconstrained:
	#somehow unconstraining finds the crash address but fails to find the actual solutoion
	#but when i try to find the actual soluton with constraints it removes the first few null bytes 
	print state.posix.dumps(0) #finds the correct offset
	eip = state.memory.load(state.regs.esp, 4, endness=state.arch.memory_endness)
	if state.se.symbolic(eip):
		#good_addr = 0x4b524f59
		good_addr = 0x594f524b
		copied_state = state.copy()
		constraint = eip == good_addr
		copied_state.add_constraints(constraint)
		if copied_state.satisfiable():
			state.add_constraints(constraint)
			print state.posix.dumps(0) #finds the correct address/output

