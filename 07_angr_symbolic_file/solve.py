#!/usr/bin/env python

import angr
import claripy
from pwn import *

find = 0x080489b0
avoid = 0x08048996
malloc_base = 0xd0000000

proj = angr.Project('./angr_symbolic_file')
state = proj.factory.blank_state(addr=0x080488e7)

#the program writes the input to the file name so we don't have to simulate the input?!?!!

password0 = claripy.BVS('password0', 8 * 64)

#SimFile needs symbolic backing
symbolic_file_backing_memory = angr.state_plugins.SimSymbolicMemory()
symbolic_file_backing_memory.set_state(state)

symbolic_file_backing_memory.store(0, password0)

simfile = angr.storage.SimFile("MDLMECFV.txt", 'r', content=symbolic_file_backing_memory, size=64)
symbolic_filesystem = {
    "MDLMECFV.txt" : simfile
}
state.posix.fs = symbolic_filesystem
simgr = proj.factory.simgr(state)

simgr.explore(find=find, avoid=avoid)

for found in simgr.found:
	simgr = proj.factory.simgr(found)
	text1 = found.se.eval(password0, cast_to=str) 
	print text1
