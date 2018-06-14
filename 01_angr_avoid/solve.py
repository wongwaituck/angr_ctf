#!/usr/bin/env python

import angr

find = 0x080485e0
avoid = 0x80485a8

proj = angr.Project('./angr_avoid')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)
for found in simgr.found:
	simgr = proj.factory.simgr(found)

	#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
	text = found.posix.dumps(0)

	print text

