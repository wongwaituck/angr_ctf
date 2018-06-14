#!/usr/bin/env python

import angr

find = []

f = open("addresses", "rt")
f_lines = f.readlines()
for l in f_lines:
	find.append(int(l, 16))

proj = angr.Project('./angr_find_cond')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

simgr.explore(find=find)
for found in simgr.found:
	simgr = proj.factory.simgr(found)

	#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
	text = found.posix.dumps(0)

	print text

