#!/usr/bin/env python

import angr
import claripy

find = 0x08048673 
to_check = "TWMWDSJLBRNVADHM"

proj = angr.Project('./angr_constraints')

state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)

password = claripy.BVS('password', len(to_check) * 8)
state.memory.store(0x804a050, password, len(to_check))

simgr.explore(find=find)
found = simgr.found[0]
simgr = proj.factory.simgr(found)

#add constraints
found_bv = found.memory.load(0x804a050, len(to_check))
constraint_expression = found_bv == to_check

# Add the constraint to the state to instruct z3 to include it when solving
# for input.
found.add_constraints(constraint_expression)

text = found.solver.eval(found_bv, cast_to=str)
text1 = found.posix.dumps(0)

print text
print text1

