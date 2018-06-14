#!/usr/bin/env python

import angr
import claripy
from pwn import *

#find = 0x08048560 
to_print = "Good Job."

def is_to_print(state):
	puts_arg = state.memory.load(state.regs.esp + 4, 4, endness=state.arch.memory_endness)
	
	if state.se.symbolic(puts_arg):
		good_job_addr=0x465a4f43
		copied_state = state.copy()
		is_vuln = puts_arg == good_job_addr
		copied_state.add_constraints(is_vuln)
		if copied_state.satisfiable():
			state.add_constraints(is_vuln)
			return True
		else:
			return False


def find_puts(state):
	puts_address = 0x8048370
	if state.addr == puts_address:
		return is_to_print(state)
	else:
		return False

proj = angr.Project('./angr_arb_read')
state = proj.factory.entry_state()

passnum = claripy.BVS('passnum', 32)
password = claripy.BVS('password', 20 * 8)

def hook_scanf(state):
	global passnum
	global password
	state.mem[0x465a7040].int = passnum
	state.memory.store(state.regs.ebp - 0x1c, password)
	for char in password.chop(bits=8):
		state.add_constraints(char > 32, char <= 126)

proj.hook(0x08048503, hook_scanf, length=5)

simgr = proj.factory.simgr(state)

simgr.explore(find=find_puts)

for found in simgr.found:
	print 'found'
	print found.solver.eval(passnum, cast_to=int)
	print found.solver.eval(password, cast_to=str)
