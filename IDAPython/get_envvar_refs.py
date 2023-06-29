import idaapi
import idautils
import ida_funcs
import idc
from idaapi import BADADDR
from ida_xref import get_first_cref_to, get_next_cref_to
from collections import namedtuple

EnvVarRef = namedtuple("EnvVarRef", ["callee", "ea", "xreffunc", "insn_ea", "insn", "length", "disasm", "regname", "op1", "refname"])

env_interesting_funcs = {
    "putenv": {"reg": "rcx"}, # varname=value -> rcx
    "putenv_s": {"reg": "rcx"}, # varname -> rcx
    "getenv_s": {"reg": "r9"}, # varname -> r9
    "getenv": {"reg": "rcx"}, # varname -> rcx
    "GetEnvironmentStrings": {"reg": "rax"}, # <= rax
    "SetEnvironmentStrings": {"reg": "rcx"}, # varblock -> rcx
    "GetEnvironmentVariableA": {"reg": "rcx"}, # varname -> rcx
    "GetEnvironmentVariableW": {"reg": "rcx"}, # varname -> rcx
    "SetEnvironmentVariableA": {"reg": "rcx"}, # varname -> rcx
    "SetEnvironmentVariableW": {"reg": "rcx"}, # varname -> rcx
    }

def reverse_walk_envvar_insns(callee, ea, xreffunc, refname):
    regname = [env_interesting_funcs[k]["reg"] for k in env_interesting_funcs.keys() if callee.endswith(k)][0]
    for fea in sorted(xreffunc.head_items(), reverse=True):
        if fea <= ea:
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, fea)
            disasm = idc.generate_disasm_line(fea, 0)
            op1 = print_operand(fea, 0)
            if regname in disasm and regname == op1:
                return EnvVarRef(callee, ea, xreffunc, fea, insn, length, disasm, regname, op1, refname)

def analyze_envvar_call(callee, ea):
    refname = idc.get_func_name(ea)
    dmngld_refname = idc.demangle_name(refname, idc.get_inf_attr(INF_SHORT_DN))
    refname = dmngld_refname if dmngld_refname else refname
    xreffunc = ida_funcs.get_func(ea)
    if xreffunc:
        return reverse_walk_envvar_insns(callee, ea, xreffunc, refname)

def main():
    env_funcs = [func for func in idautils.Names() if any(func[1].endswith(name) and "MsvcEtw" not in func[1] for name in env_interesting_funcs)]
    env_refs = {}
    for ea, name in env_funcs:
        if (ea, name,) in env_refs:
            continue
        refsbyea = {}
        for ref in idautils.XrefsTo(ea):
            refsbyea[ref.frm] = analyze_envvar_call(name, ref.frm)
        env_refs[(ea, name,)] = refsbyea
    for (ea, name), byea_dict in env_refs.items():
        print(f"{ea:#x}: {name}() called by:")
        for insn_ea, byea in byea_dict.items(): 
            print(f"  {byea.insn_ea:#x}: {byea.disasm}")

if __name__ == "__main__":
    main()
