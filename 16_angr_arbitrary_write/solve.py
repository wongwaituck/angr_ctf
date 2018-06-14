#!/usr/bin/env python

import angr
import claripy
from pwn import *

def is_bad_strncpy(state):
	strncpy_dest_arg = state.memory.load(state.regs.esp + 4, 4, endness=state.arch.memory_endness)
	strncpy_src_arg = state.memory.load(state.regs.esp + 8, 4, endness=state.arch.memory_endness)
	src_data = state.memory.load(strncpy_src_arg, 8)
	if state.se.symbolic(strncpy_dest_arg) and state.se.symbolic(src_data):
		pass_addr = 0x8048729
		dst_data = state.memory.load(pass_addr, 8)
		copied_state = state.copy()
		is_good_pass = src_data == dst_data
		is_good_dest = strncpy_dest_arg == 0x49455854
		copied_state.add_constraints(is_good_pass, is_good_dest)
		if copied_state.satisfiable():
			state.add_constraints(is_good_pass, is_good_dest)
			return True
		else:
			return False

def find_strncpy(state):
	strncpy_address = 0x8048410
	if state.addr == strncpy_address:
		return is_bad_strncpy(state)
	else:
		return False

proj = angr.Project('./angr_arb_write')
state = proj.factory.entry_state()

passnum = claripy.BVS('passnum', 32)
password = claripy.BVS('password', 20 * 8)

def hook_scanf(state):
	global passnum
	global password
	state.mem[0x49455864].int = passnum
	state.memory.store(state.regs.ebp - 0x1c, password)
	for char in password.chop(bits=8):
		state.add_constraints(char > 32, char <= 126)

proj.hook(0x080485cc, hook_scanf, length=5)

simgr = proj.factory.simgr(state)

simgr.explore(find=find_strncpy)

for found in simgr.found:
	print 'found'
	print found.solver.eval(passnum, cast_to=int)
	print found.solver.eval(password, cast_to=str)
