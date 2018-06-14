#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x772
base = 0x0
proj = angr.Project('./libangr_shared.so', load_options={
	'main_opts' : {
		'custom_base_addr' : base
	}
})
state = proj.factory.blank_state(addr=0x6da)

password = claripy.BVS('password', 8 * 8)
state.memory.store(0x10000, password)
state.memory.store(state.regs.ebp + 8, 0x10000, endness=proj.arch.memory_endness)

simgr = proj.factory.simgr(state)

simgr.explore(find=find)

for found in simgr.found:
	constraint = found.regs.eax == 0
	found.add_constraints(constraint)
	print found.solver.eval(password, cast_to=str)
