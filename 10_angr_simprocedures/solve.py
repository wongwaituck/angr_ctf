#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x0804a984 
avoid = 0x0804a972  
evil = "CTUTQFNGHIDEHORG"

class CheckEquals(angr.SimProcedure):
	def run(self, to_check, length):
		string = self.state.memory.load(to_check, length)
		return claripy.If(string == evil, claripy.BVV(1, 32), claripy.BVV(0, 32))

sym = "check_equals_CTUTQFNGHIDEHORG"

proj = angr.Project('./angr_simproc')

state = proj.factory.entry_state()

proj.hook_symbol(sym, CheckEquals()) 

simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	print found.posix.dumps(0)[:16]
