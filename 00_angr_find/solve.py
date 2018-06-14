#!/usr/bin/env python

import angr

find = 0x08048678
avoid = 0x08048666

proj = angr.Project('./angr_find')
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)
found = simgr.found[0]
simgr = proj.factory.simgr(found)

#text = found.solver.eval(found.memory.load(found.regs.ebp - 0x1a, 21), cast_to=str)
text = found.posix.dumps(0)

print text

