#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x080486e4
avoid = 0x080486d2
proj = angr.Project('./angr_symbolic_stack')
state = proj.factory.blank_state(addr=0x08048694)

password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)

state.mem[state.regs.ebp - 0xc].int = password0
state.mem[state.regs.ebp - 0x10].int = password1

simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)
for found in simgr.found:
	simgr = proj.factory.simgr(found)
	#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
	text = found.se.eval(password0)
	text1 = found.se.eval(password1)

	print text, text1
