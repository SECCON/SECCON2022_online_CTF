import angr
import claripy
from logging import getLogger, WARN

getLogger("angr").setLevel(WARN + 1)
getLogger("claripy").setLevel(WARN + 1)

flag = claripy.BVS("flag", 64*8)

p = angr.Project("../files/chall.baby", load_options={"auto_load_libs": False})
state = p.factory.entry_state(args=["../files/chall.baby", flag])
simgr = p.factory.simulation_manager(state)

x = simgr.explore(find=0x4012c2, avoid=0x401273)
print(x.found[0].solver.eval(flag, cast_to=bytes))
