#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x0804866d 
avoid = 0x0804865b 

proj = angr.Project('./angr_symbolic_mem')
state = proj.factory.blank_state(addr=0x080485fe)

password0 = claripy.BVS('password0', 64)
password1 = claripy.BVS('password1', 64)
password2 = claripy.BVS('password2', 64)
password3 = claripy.BVS('password3', 64)

state.memory.store(0x984a3c0, password0)
state.memory.store(0x984a3c8, password1)
state.memory.store(0x984a3d0, password2)
state.memory.store(0x984a3d8, password3)

simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)
for found in simgr.found:
	simgr = proj.factory.simgr(found)
	#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
	text = found.se.eval(password0, cast_to=str)
	text1 = found.se.eval(password1, cast_to=str)
	text2 = found.se.eval(password2, cast_to=str)
	text3 = found.se.eval(password3, cast_to=str)

	print text, text1, text2, text3
