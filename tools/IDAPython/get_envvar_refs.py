import idaapi
import idautils
import ida_bytes
import ida_funcs
import idc
from collections import namedtuple
from typing import Optional

EnvVarRef = namedtuple("EnvVarRef", ["callee", "ea", "xreffunc", "insn_ea", "insn", "length", "disasm", "regname", "op1", "refname"])
Op = namedtuple("Op", ["op", "type", "value", "strlit"])

env_interesting_funcs = {
    "putenv": {"reg": "rcx"},  # varname=value -> rcx
    "putenv_s": {"reg": "rcx"},  # varname -> rcx
    "getenv_s": {"reg": "r9"},  # varname -> r9
    "getenv": {"reg": "rcx"},  # varname -> rcx
    "dupenv_s": {"reg": "r8"},  # varname -> r8
    "GetEnvironmentStrings": {"reg": "rax"},  # <= rax
    "SetEnvironmentStrings": {"reg": "rcx"},  # varblock -> rcx
    "GetEnvironmentVariableA": {"reg": "rcx"},  # varname -> rcx
    "GetEnvironmentVariableW": {"reg": "rcx"},  # varname -> rcx
    "SetEnvironmentVariableA": {"reg": "rcx"},  # varname -> rcx
    "SetEnvironmentVariableW": {"reg": "rcx"},  # varname -> rcx
}


def reverse_walk_envvar_insns(callee: str, ea: int, xreffunc, refname: str) -> EnvVarRef:
    regname = [env_interesting_funcs[k]["reg"] for k in env_interesting_funcs.keys() if callee.endswith(k)][0]
    for fea in sorted(xreffunc.head_items(), reverse=True):
        if fea <= ea:
            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, fea)
            disasm = idc.generate_disasm_line(fea, 0)
            if idc.print_insn_mnem(fea) not in {"mov", "lea"}:
                continue
            op1 = idc.print_operand(fea, 0)
            if regname in disasm and regname == op1:
                return EnvVarRef(callee, ea, xreffunc, fea, insn, length, disasm, regname, op1, refname)


def get_refname(ea: int, demangle: bool = True) -> str:
    refname = idc.get_func_name(ea)
    dmngld_refname = idc.demangle_name(refname, idc.get_inf_attr(idc.INF_SHORT_DN))
    return dmngld_refname if dmngld_refname else refname


def analyze_envvar_call(callee: str, ea: int) -> Optional[EnvVarRef]:
    refname = get_refname(ea)
    xreffunc = ida_funcs.get_func(ea)
    if xreffunc:
        return reverse_walk_envvar_insns(callee, ea, xreffunc, refname)


def clear_output_console():
    form = idaapi.find_widget("Output window")
    idaapi.activate_widget(form, True)
    idaapi.process_ui_action("msglist:Clear")


def get_op_details(ea: int, opidx: int) -> Op:
    op = idc.print_operand(ea, opidx)
    optype = idc.get_operand_type(ea, opidx)
    opvalue = idc.get_operand_value(ea, opidx)
    strlit = None
    if optype in {idc.o_mem} and opvalue != -1:
        flags = ida_bytes.get_flags(opvalue)
        if ida_bytes.is_strlit(flags):
            strtype = idc.get_str_type(opvalue)
            strlit = idc.get_strlit_contents(opvalue, -1, strtype)
            if strlit is not None:
                strlit = strlit.decode("utf-8")
    return Op(op, optype, opvalue, strlit)


def rename_and_retype_function(oldname: str, newname: str, newtype: str, warn: bool = True, tinfo_flags=idc.TINFO_DEFINITE):
    matches = [name for name in idautils.Names() if oldname == name[1]]
    if matches and len(matches) == 1:
        matches = matches[0]
        ea, name = matches
        print(f"{ea=:#x} -> {name=}")
        tp = idc.parse_decl(newtype.format(**locals()), 0)
        assert tp is not None, f"ERROR: Could not parse function type {newtype=}"
        if not idc.apply_type(ea, tp, tinfo_flags):
            print(f"ERROR: Failed to apply function type {newtype=} at {ea:#x}")
        if not idc.set_name(ea, newname):
            print(f"ERROR: Failed to rename {oldname=} to {newname=}")
    elif not matches:
        ...
    elif warn:
        print(f"WARNING: failed renaming '{oldname=}' to '{newname=}': '{newtype}'. Perhaps this helps: {matches=}")


def detect_environment_variables():
    env_funcs = [func for func in idautils.Names() if any(func[1].endswith(name) and "MsvcEtw" not in func[1] for name in env_interesting_funcs)]
    env_refs = {}
    env_varnames = set()
    print(60 * "=")
    for ea, name in env_funcs:
        key = (ea, name,)  # fmt: skip
        if key in env_refs:
            continue
        refsbyea = {}
        for ref in idautils.XrefsTo(ea):
            refsbyea[ref.frm] = analyze_envvar_call(name, ref.frm)
        env_refs[key] = refsbyea
    digdeeper = {}
    slotidx = 1023
    for (ea, name), byea_dict in env_refs.items():
        print(f"{ea:#x}: {name}() called by:")
        for insn_ea, byea in byea_dict.items():
            if byea is None:
                print(f"No info for state leading up to call of {name} at {insn_ea:#x}")
                continue
            if byea.insn_ea is None:
                print(f"No instruction EA for : {byea}")
                continue
            op2 = get_op_details(byea.insn_ea, 1)
            if op2.strlit:
                env_varnames.add(op2.strlit)
                print(f'  {byea.insn_ea:#x} => {op2.value:#x}: "{op2.strlit}" {byea.refname:>55}')
                idc.set_name(op2.value, f"szEnvVar_{op2.strlit}")
                cmt = f"Environment variable: '{op2.strlit}'"
                idc.set_cmt(byea.insn_ea, cmt, 0)
                idc.set_color(byea.insn_ea, idc.CIC_ITEM, 0xB1CEFB)  # "apricot"
                ida_idc.mark_position(op2.value, 1, 0, 0, slotidx, cmt)
                slotidx -= 1
                # TODO: set color?
            else:  # those are candidates for a deeper search
                digdeeper[insn_ea] = byea
                print(f"  {byea.insn_ea:#x} => {op2.value:#x}: {byea.disasm} ({op2.type=}) {byea.refname:>55}")
                idc.set_color(byea.insn_ea, idc.CIC_ITEM, 0x35E1FF)  # "banana"
                idc.set_color(ea, idc.CIC_ITEM, 0x30E1F0)  # "dandelion"
    print(60 * "=")
    interesting_func_eas = {}
    for ea, byea in digdeeper.items():
        if byea.xreffunc.start_ea not in interesting_func_eas:
            interesting_func_eas[byea.xreffunc.start_ea] = []
            interesting_func_eas[byea.xreffunc.start_ea].append(byea)
        else:
            interesting_func_eas[byea.xreffunc.start_ea].append(byea)
    print(f"{len(interesting_func_eas)} functions look interesting")
    for ea, byea_list in interesting_func_eas.items():
        calls = set([i for i in idautils.FuncItems(ea) for x in idautils.XrefsFrom(i) if x.type in {idaapi.fl_CF, idaapi.fl_CN}])
        impcalls = [c for c in calls if any(name in idc.generate_disasm_line(c, 0) for name in env_interesting_funcs)]
        if impcalls:
            idc.set_color(ea, idc.CIC_FUNC, 0xD6EAF0)  # "eggshell"
            refname = get_refname(ea)
            cmt = f"Env. var. processing func.: '{refname}'"
            ida_idc.mark_position(ea, 1, 0, 0, slotidx, cmt)
            slotidx -= 1
            print(f"{ea:#x} aka {refname} is interesting, {len(impcalls)} imports called:")
            for call in impcalls:
                disasm = idc.generate_disasm_line(call, 0)
                print(f"{call:#x} -> {disasm}")
    print(60 * "=")
    for varname in sorted(env_varnames):
        print(varname)


def main():
    clear_output_console()
    rename_and_retype_function("main", "wmain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?wmainInner@@YAHHQEAPEAG@Z", "wmainInner", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?HelperMain@@YAHHQEAPEAG@Z", "HelperMain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?LibrarianMain@@YAHHQEAPEAG@Z", "LibrarianMain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?EditorMain@@YAHHQEAPEAG@Z", "EditorMain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?CvtCilMain@@YAHHQEAPEAG@Z", "CvtCilMain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?DumperMain@@YAHHQEAPEAG@Z", "DumperMain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?LinkerMain@@YAHHQEAPEAG@Z", "LinkerMain", "int {newname}(int argc, wchar_t** argv);")
    rename_and_retype_function("?Message@@YAXIZZ", "Message", "void {newname}(unsigned int, ...);")
    rename_and_retype_function("?ProcessCommandFile@@YAXPEBG@Z", "ProcessCommandFile", "void {newname}(wchar_t const* name);")
    rename_and_retype_function(
        "?link_wfsopen@@YAPEAU_iobuf@@PEBG0H@Z", "link_wfsopen", "void {newname}(wchar_t const* filename, wchar_t const* mode, int shflag);"
    )
    rename_and_retype_function("?link_ftell@@YAJPEAU_iobuf@@@Z", "link_ftell", "off_t {newname}(FILE* stream);")
    rename_and_retype_function("?link_fseek@@YAHPEAU_iobuf@@JH@Z", "link_fseek", "int {newname}(FILE* stream, off_t offset, int origin);")
    rename_and_retype_function("?link_fclose@@YAHPEAU_iobuf@@@Z", "link_fclose", "int {newname}(FILE* stream);")
    rename_and_retype_function("?SzTrimFile@@YAPEADPEBD@Z", "SzTrimFile", "char* {newname}(char const* string1);")
    rename_and_retype_function("?SzDupWsz@@YAPEADPEBG@Z", "SzDupWsz", "char* {newname}(LPCWCH lpWideCharStr);")
    # ?DisplayMessage@@YAXPEBG_KW4MSGTYPE@@IPEAD@Z
    # ?ParseCommandString@@YAXPEAG@Z
    # ?ParseCommandLine@@YAXHQEBQEAGPEBG1_N@Z
    # ?FParseMajorMinorVersion@@YA_NPEBGAEAK1AEA_N@Z
    # ?FParseWin32Version@@YA_NPEBGAEAKAEA_N@Z
    # FPrescanSwitch
    #
    detect_environment_variables()


if __name__ == "__main__":
    main()
# idaapi.refresh_idaview_anyway()
