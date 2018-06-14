#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x080489a7
avoid = 0x08048995 
proj = angr.Project('./angr_symbolic_reg')
state = proj.factory.blank_state(addr=0x0804893e)

password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)
password2 = claripy.BVS('password2', 32)

state.regs.eax = password0
state.regs.ebx = password1
state.regs.edx = password2

simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)
for found in simgr.found:
	simgr = proj.factory.simgr(found)
	#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
	text = found.se.eval(password0)
	text1 = found.se.eval(password1)
	text2 = found.se.eval(password2)

	print hex((text))[2:], hex((text1))[2:], hex((text2))[2:]
