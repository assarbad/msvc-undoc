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


toolchain_renames = {
    "link.exe": {
        "main": ("wmain", "int {newname}(int argc, wchar_t** argv);"),
        "?wmainInner@@YAHHQEAPEAG@Z": ("wmainInner", "int {newname}(int argc, wchar_t** argv);"),
        "?HelperMain@@YAHHQEAPEAG@Z": ("HelperMain", "int {newname}(int argc, wchar_t** argv);"),
        "?LibrarianMain@@YAHHQEAPEAG@Z": ("LibrarianMain", "int {newname}(int argc, wchar_t** argv);"),
        "?EditorMain@@YAHHQEAPEAG@Z": ("EditorMain", "int {newname}(int argc, wchar_t** argv);"),
        "?CvtCilMain@@YAHHQEAPEAG@Z": ("CvtCilMain", "int {newname}(int argc, wchar_t** argv);"),
        "?DumperMain@@YAHHQEAPEAG@Z": ("DumperMain", "int {newname}(int argc, wchar_t** argv);"),
        "?LinkerMain@@YAHHQEAPEAG@Z": ("LinkerMain", "int {newname}(int argc, wchar_t** argv);"),
        "?HybridPushThunkObjMain@@YAHHQEAPEAG@Z": ("HybridPushThunkObjMain", "int {newname}(int argc, wchar_t** argv);"),
        "?Message@@YAXIZZ": ("Message", "void {newname}(unsigned int, ...);"),
        "?ProcessCommandFile@@YAXPEBG@Z": ("ProcessCommandFile", "void {newname}(wchar_t const* name);"),
        "?link_wfsopen@@YAPEAU_iobuf@@PEBG0H@Z": ("link_wfsopen", "FILE* {newname}(wchar_t const* filename, wchar_t const* mode, int shflag);"),
        "?link_ftell@@YAJPEAU_iobuf@@@Z": ("link_ftell", "off_t {newname}(FILE* stream);"),
        "?link_fseek@@YAHPEAU_iobuf@@JH@Z": ("link_fseek", "int {newname}(FILE* stream, off_t offset, int origin);"),
        "?link_fclose@@YAHPEAU_iobuf@@@Z": ("link_fclose", "int {newname}(FILE* stream);"),
        "?SzTrimFile@@YAPEADPEBD@Z": ("SzTrimFile", "char* {newname}(char const* string1);"),
        "?SzDupWsz@@YAPEADPEBG@Z": ("SzDupWsz", "char* {newname}(LPCWCH lpWideCharStr);"),
        "?SHA1Update@SHA1Hash@@AEAAXPEAUSHA1_CTX@@PEBEK@Z": (
            "SHA1Hash__SHA1Update",
            "void {newname}(SHA1Hash *__hidden this, struct SHA1_CTX *, uchar const* buf, ulong buflen);",
        ),
        "?OutputInit@@YAXXZ": ("OutputInit", "void {newname}();"),
        "FIsConsole": ("FIsConsole", "bool {newname}(FILE *stream);"),
        "?ControlCHandler@@YAHK@Z": ("ControlCHandler", "BOOL {newname}(DWORD CtrlType);"),
        "?EndEnmUndefExtNonWeak@@YAXPEAVENM_UNDEF_EXT@@@Z": (
            "EndEnmUndefExtNonWeak",
            "void __cdecl {newname}(wchar_t const* expression, wchar_t const* function, wchar_t const* file, uint line, uintptr_t);",
        ),
        "?PrintLogo@@YAXXZ": ("PrintLogo", "void PrintLogo(void);"),
        ### Data
        "?Dbflags@@3PADA": ("Dbflags", "bool Dbflags[73];"),  # TODO: make array 73 elements
        "?ToolName@@3PEBGEB": ("ToolName", "wchar_t* ToolName;"),
        "?g_dwMainThreadId@@3KA": ("g_dwMainThreadId", "DWORD g_dwMainThreadId;"),
        "?g_cbILKMax@@3_KA": ("g_cbILKMax", "uint64_t g_cbILKMax;"),
        "?szPdbFilename@@3PEAGEA": ("szPdbFilename", "LPCWCH {newname};"),
        "?g_szLTCGOutFilename@@3PEBGEB": ("g_szLTCGOutFilename", "LPCWSTR {newname};"),
        "?fNoLogo@@3_NA": ("fNoLogo", "bool {newname};"),
        "?g_fPrescanSwitches@@3_NA": ("g_fPrescanSwitches", "bool {newname};"),
        "?fUnInitWarbird@@3_NA": ("fUnInitWarbird", "bool {newname};"),
        "?fWarningIsError@@3_NA": ("fWarningIsError", "bool {newname};"),
        "?g_fFastFail@@3_NA": ("g_fFastFail", "bool {newname};"),
        "?g_fInferAsanLibsDone@@3_NA": ("g_fInferAsanLibsDone", "bool {newname};"),
        "?g_fForceNoLinkRepro@@3_NA": ("g_fForceNoLinkRepro", "bool {newname};"),
        "?g_fForceNoOnfailRepro@@3_NA": ("g_fForceNoOnfailRepro", "bool {newname};"),
        "?g_fLtcgForcedOff@@3_NA": ("g_fLtcgForcedOff", "bool {newname};"),
        "?g_fArm64XCrossDebug@@3_NA": ("g_fArm64XCrossDebug", "bool {newname};"),
        "?g_fArm64XCrossResolve@@3_NA": ("g_fArm64XCrossResolve", "bool {newname};"),
        "?g_fArm64XHack@@3_NA": ("g_fArm64XHack", "bool {newname};"),
        "?g_fSEHEmpty@@3_NA": ("g_fSEHEmpty", "bool {newname};"),
        "?fNoBaseRelocs@@3_NA": ("fNoBaseRelocs", "bool {newname};"),
        "?fUnInitWarbird@@3_NA": ("fUnInitWarbird", "bool {newname};"),
        "?fDidMachineDependentInit@@3_NA": ("fDidMachineDependentInit", "bool {newname};"),
        "?fMultipleDefinitions@@3_NA": ("fMultipleDefinitions", "bool {newname};"),
        "?g_fWowA64LinkerGeneratedLib@@3_NA": ("g_fWowA64LinkerGeneratedLib", "bool {newname};"),
        "?g_fForcePGORepro@@3_NA": ("g_fForcePGORepro", "bool {newname};"),
        "?g_fPGU@@3_NA": ("g_fPGU", "bool {newname};"),
        "?g_fPGO@@3_NA": ("g_fPGO", "bool {newname};"),
        "?g_fPGI@@3_NA": ("g_fPGI", "bool {newname};"),
        "?g_fDidPass1DefFile@@3_NA": ("g_fDidPass1DefFile", "bool {newname};"),
        "?fWbrdReportErrors@@3_NA": ("fWbrdReportErrors", "bool {newname};"),
        "?fWbrdTestEncrypt@@3_NA": ("fWbrdTestEncrypt", "bool {newname};"),
        "?g_fIncrClean@@3_NA": ("g_fIncrClean", "bool {newname};"),
        "?g_fSawCIL@@3_NA": ("g_fSawCIL", "bool {newname};"),
        "?g_fSawWinRTMeta@@3_NA": ("g_fSawWinRTMeta", "bool {newname};"),
        "?g_fClearLinkRepro@@3_NA": ("g_fClearLinkRepro", "bool {newname};"),
        "?fOpenedOutFilename@@3_NA": ("fOpenedOutFilename", "bool {newname};"),
        "?g_fRunBelow4GB@@3_NA": ("g_fRunBelow4GB", "bool {newname};"),
        "?g_fObjCoffInitialized@@3_NA": ("g_fObjCoffInitialized", "bool {newname};"),
        "?g_fWarnZwObjInStaticLib@@3_NA": ("g_fWarnZwObjInStaticLib", "bool {newname};"),
        "?fDidInitRgci@@3_NA": ("fDidInitRgci", "bool {newname};"),
        "?g_fResolvePlaceholderTlsIndexImport@@3_NA": ("g_fResolvePlaceholderTlsIndexImport", "bool {newname};"),
        "?fErr@@3_NA": ("fErr", "bool {newname};"),
        # "?ToolType@@3PAUcalltype@@A": ("ToolType", "calltype ToolType;"), # TODO: make array of 8 elements (define struct)
        # struct {wchar_t *ToolName; wchar_t *ExecutableName; wchar_t *ParamName; char Unknown[8]; int (__stdcall *MainFunc)(int argc, wchar_t **argv);};
    },
}


def retype_single(oldname: str, newname: str, rule: tuple, tinfo_flags=idc.TINFO_DEFINITE) -> bool:
    (ea, name), newtype = rule
    if newtype is None:
        return False, f"INFO: no new type for {oldname}/{newname}"
    newtype = newtype.format(**locals())
    tp = idc.parse_decl(newtype, 0)
    if tp is None:
        return False, f"ERROR: Could not parse '{newname}' function type {newtype=}"
    if not idc.apply_type(ea, tp, tinfo_flags):
        return False, f"{ea:#x}: ERROR: Failed to apply function type => {newtype}"
    return True, f"{ea:#x}: INFO: Re-typed {name} => {newtype}"


def rename_single(oldname: str, newname: str, rule: tuple) -> bool:
    (ea, _), _ = rule
    if not idc.set_name(ea, newname):
        return False, f"{ea:#x}: ERROR: Failed to rename {oldname=} to {newname=}"
    return True, f"{ea:#x}: INFO: Renamed {oldname=} to {newname=}" if oldname != newname else None


def rename_and_retype(renames: dict, verbose: bool = True):
    rfname = idc.get_root_filename()  # get_input_file_path() for IDB _path_
    assert rfname, "Could not retrieve name of the file used to create the IDB"
    if rfname not in renames:
        print(f"Could not find '{rfname}' as top-level key in the renaming rules")
    print(f"INFO: applying renaming and re-typing rules for '{rfname}'")
    rules = renames[rfname]
    # Determine the items that were already renamed and those we need to rename
    renames = {(oldnm, rules[oldnm][0]): (nm, *rules[oldnm][1:]) for nm in idautils.Names() for oldnm in rules if oldnm == nm[1] and oldnm != rules[oldnm][0]}
    renamed = {(oldnm, rules[oldnm][0]): (nm, *rules[oldnm][1:]) for nm in idautils.Names() for oldnm in rules if rules[oldnm][0] == nm[1]}
    rule_count = len(rules)
    accounted_for_rule_count = len(renames) + len(renamed)
    print(f"INFO: {len(renames)} items to rename, {len(renamed)} already renamed, {rule_count - accounted_for_rule_count} missing from IDB")
    if verbose and rule_count != accounted_for_rule_count:
        print(f"WARNING: {rule_count=} <> {accounted_for_rule_count=} ({len(rules)=})")
    if renames:
        print(50 * "=", "[RENAMES]", 10 * "=")
        for (oldname, newname), rule in renames.items():
            success, msg = retype_single(oldname, newname, rule)
            if verbose and msg:
                print(msg)
            success, msg = rename_single(oldname, newname, rule)
            if verbose and msg:
                print(msg)
    if renamed:
        print(50 * "=", "[RENAMED]", 10 * "=")
        for (oldname, newname), rule in renamed.items():
            success, msg = retype_single(oldname, newname, rule)
            if verbose and msg:
                print(msg)


def main():
    clear_output_console()
    rename_and_retype(toolchain_renames)
    # detect_environment_variables()


if __name__ == "__main__":
    main()
# idaapi.refresh_idaview_anyway()
