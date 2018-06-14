#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x0804fc9c  
avoid = 0x0804fc8a  
#numsolns
i = 0
class SimScanF(angr.SimProcedure):
	def run(self, fmt_str, a, b):
		global i
		soln1 = claripy.BVS('soln' + str(i), 32)
		i += 1
		soln2 = claripy.BVS('soln' + str(i), 32)
		i += 1

		self.state.mem[a].int = soln1
		self.state.mem[b].int = soln2

		self.state.globals['soln' + str(i/2)] = (soln1, soln2)
		print i
		return claripy.BVV(1, 32)

proj = angr.Project('./angr_sim_scanf')
state = proj.factory.entry_state()
proj.hook(0x8048450, SimScanF(), length=5) 

simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	print 'found'
	print i
	for j in range(2, i+1, 2):
		gl = found.globals['soln' + str(i/2)]
		print found.solver.eval(gl[0], cast_to=int), found.solver.eval(gl[1], cast_to=int)
