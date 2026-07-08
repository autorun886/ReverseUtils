from z3 import BitVec, BitVecVal, UDiv, URem, LShR, UGT, UGE, ULT, ULE, prove


print('Testing:  neg      (ebp.4+ #1.4 ) , ebp.4 ==  bnot    ebp.4, ebp.4')
x_0 = BitVec('x_0', 32)
original_expr = -((x_0 + 1))
new_expr = ~(x_0)
prove(original_expr == new_expr)

print('Testing:  bnot     (esi.4 ^  #0x71F41E29.4 ) , esi.4 ==  xor     esi.4,  #0x8E0BE1D6.4 , esi.4')
x_0 = BitVec('x_0', 32)
original_expr = ~((x_0 ^ 1911823913))
new_expr = (x_0 ^ 2383143382)
prove(original_expr == new_expr)

print('Testing:  xor      bnot(ebx.4) ,  #0x726D6B35.4 , ebx.4 ==  bnot     ( #0x726D6B35.4  ^ ebx.4) , ebx.4')
x_0 = BitVec('x_0', 32)
original_expr = (~(x_0) ^ 1919773493)
new_expr = ~((1919773493 ^ x_0))
prove(original_expr == new_expr)

print('Testing:  bnot     (ebx.4 ^  #0x726D6B35.4 ) , ebx.4 ==  xor     ebx.4,  #0x8D9294CA.4 , ebx.4')
x_0 = BitVec('x_0', 32)
original_expr = ~((x_0 ^ 1919773493))
new_expr = (x_0 ^ 2375193802)
prove(original_expr == new_expr)

print('Testing:  add      (%lpProcName.4-&(%ModuleName).4) ,  (&(%ModuleName{22}).4+edx.4{23}) , .4 ==  sub      (%lpProcName.4+edx.4{23}) ,  #0.4 , .4')
x_0 = BitVec('x_0', 32)
x_1 = BitVec('x_1', 32)
x_2 = BitVec('x_2', 32)
original_expr = ((x_0 - x_1) + (x_1 + x_2))
new_expr = ((x_0 + x_2) - 0)
prove(original_expr == new_expr)

