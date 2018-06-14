#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x08048759 
avoid = 0x08048747
malloc_base = 0xd0000000

old1 = 0xbf26ff4
old2 = 0xbf26ffc

proj = angr.Project('./angr_symbolic_dyn')
state = proj.factory.blank_state(addr=0x08048696)

password0 = claripy.BVS('password0', 64)
password1 = claripy.BVS('password1', 64)

state.memory.store(malloc_base + 4, password0)
state.memory.store(malloc_base + 20, password1)

state.memory.store(old1, malloc_base + 4,  endness=proj.arch.memory_endness)
state.memory.store(old2, malloc_base + 20, endness=proj.arch.memory_endness)

'''
malloc_plt = proj.loader.main_object.plt['malloc']
scanf_plt = proj.loader.main_object.plt['__isoc99_scanf']

#hook malloc_plt
proj.hook(malloc_plt, fake_malloc)
proj.hook(scanf_plt, fake_scanf)
'''

simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)
for found in simgr.found:
	simgr = proj.factory.simgr(found)
	#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
	text = found.se.eval(password0, cast_to=str)
	text1 = found.se.eval(password1, cast_to=str)

	print text, text1
