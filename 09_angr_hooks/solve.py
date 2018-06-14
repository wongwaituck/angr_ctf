#!/usr/bin/env python

import angr
import claripy
from pwn import *

find1 = 0x080486ae 
find2 = 0x08048768
avoid = 0x08048756 
to_check = "NASFDURYLNYHSIXX"

def fake_eq(state):
	pass

proj = angr.Project('./angr_hooks')

state = proj.factory.entry_state()

password0 = claripy.BVS('password0', 8 * 16)
state.memory.store(0x804a054, password0, 16)

proj.hook(0x080486b3, fake_eq, 5) 

simgr = proj.factory.simgr(state)

simgr.explore(find=find1, avoid=avoid)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	text1 = found.se.eval(password0, cast_to=str) 
	found_bv = found.memory.load(0x804a054, 16)

	constraint = found_bv == to_check
	found.add_constraints(constraint)
	text = found.solver.eval(found_bv, cast_to=str)
	print found.posix.dumps(0)[:16]

state = proj.factory.entry_state()

password1 = claripy.BVS('password1', 8 * 16)
state.memory.store(0x804a054, password1, 16)

simgr = proj.factory.simgr(state)

simgr.explore(find=find2, avoid=avoid)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	text1 = found.se.eval(password1, cast_to=str) 
	found_bv = found.memory.load(0x804a054, 16)

	constraint = password1 == to_check
	found.add_constraints(constraint)
	text = found.solver.eval(password1, cast_to=str)
	print found.posix.dumps(0)[16:32]
