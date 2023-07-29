import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_idc
import ida_struct
import ida_typeinf
import ida_xref
import idc
import re
from collections import namedtuple
from functools import partial
from typing import Optional, Tuple

# colors via https://latexcolor.com/

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


slotidx = 1023
marked_positions_ea = {}


def set_color(ea: int, what: int, color: int) -> Tuple[Optional[bool], Optional[str]]:
    valid_whats = {idc.CIC_ITEM, idc.CIC_FUNC, idc.CIC_SEGM}
    if what not in valid_whats:
        return False, f"invalid {what=} for {ea:#x}, the following are valid: {valid_whats=}"
    oldclr = idc.get_color(ea, what)
    if oldclr != color:  # need to apply a color?
        retval = idc.set_color(ea, what, color)
        if retval:
            return True, f"applied color {color&0xffffff:#x} to {ea:#x} (old: {oldclr&0xffffff:#x}"
        return False, f"failed to apply color {color&0xffffff:#x} to {ea:#x} (old: {oldclr&0xffffff:#x}"
    return None, None  # indicate nothing was done


def set_color_code_or_else_with_carp(ea: int, code_color: int, else_color: Optional[int] = None) -> bool:
    """\
        Sets color on code (function) -- checked by this function -- or item (anything else) to the given value or does nothing!

        Errors are reported via print(), success is silently ignored

        Returns: True upon success, False upon failure and None if no action was taken (not data/code or color was already applied)
    """
    flags = ida_bytes.get_flags(ea)
    ret, msg = None, None
    if ida_bytes.is_code(flags):
        ret, msg = set_color(ea, idc.CIC_FUNC, code_color)
    else:
        ret, msg = set_color(ea, idc.CIC_ITEM, else_color or code_color)
    if ret or ret is None:
        return ret
    print(f"ERROR: {msg}")
    return False


def add_func_flags(ea: int, flags_to_add: int) -> bool:
    flags = ida_bytes.get_flags(ea)
    if not ida_bytes.is_code(flags):
        return None  # nothing was done, because it was data
    oldflags = idc.get_func_flags(ea)
    if oldflags in {-1}:
        print(f"WARNING: could not retrieve existing function flags at {ea:#x}, unable to add new flags.")
    else:
        if oldflags & flags_to_add == flags_to_add:
            return None  # indicate nothing was done, but distinct from failure
        else:
            if idc.set_func_flags(ea, flags_to_add | oldflags):
                return True
            print(f"WARNING: failed to set function flags at {ea:#x}. {oldflags=:#x}, {flags_to_add=:#x}")
    return False


def mark_position(ea: int, cmt: str):
    global slotidx
    global marked_positions_ea
    if ea not in marked_positions_ea:
        ida_idc.mark_position(ea, 1, 0, 0, slotidx, cmt)
        marked_positions_ea[ea] = slotidx  # remember slot
        slotidx -= 1
    else:
        oldslotidx = marked_positions_ea[ea]
        oldcmt = ida_idc.get_mark_comment(oldslotidx)
        if cmt != oldcmt:
            print(f"WARNING: attempt to mark {ea:#x} with comment: {cmt}")
            print(f"INFO: {ea:#x} has existing comment: {oldcmt}")


def get_strlit(ea) -> Optional[str]:
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_strlit(flags):
        strtype = idc.get_str_type(ea)
        strlit = idc.get_strlit_contents(ea, -1, strtype)
        if strlit is not None:
            strlit = strlit.decode("utf-8")
            return strlit
    return None


def sizeof(typestr: str) -> int:
    ti = ida_typeinf.tinfo_t()
    if ti.get_named_type(None, typestr):
        assert ti.present(), f"{typestr} isn't really present"
        return ti.get_size()
    return -1


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
    if demangle:
        dmngld_refname = idc.demangle_name(refname, idc.get_inf_attr(idc.INF_SHORT_DN))
        return dmngld_refname if dmngld_refname else refname
    return refname


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
        strlit = get_strlit(opvalue)
    return Op(op, optype, opvalue, strlit)


def detect_environment_variables():
    env_funcs = [func for func in idautils.Names() if any(func[1].endswith(name) and "MsvcEtw" not in func[1] for name in env_interesting_funcs)]
    env_refs = {}
    env_varnames = {}
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
                env_varnames[op2.strlit] = op2.value
                print(f'  {byea.insn_ea:#x} => {op2.value:#x}: "{op2.strlit}" {byea.refname:>55}')
                idc.set_name(op2.value, f"szEnvVar_{op2.strlit}")
                cmt = f"Variable(env): '{op2.strlit}'"
                idc.set_cmt(byea.insn_ea, cmt, False)
                set_color_code_or_else_with_carp(byea.insn_ea, 0xB1CEFB)  # "apricot"
                mark_position(op2.value, cmt)
            else:  # those are candidates for a deeper search
                digdeeper[insn_ea] = byea
                print(f"  {byea.insn_ea:#x} => {op2.value:#x}: {byea.disasm} ({op2.type=}) {byea.refname:>55}")
                set_color_code_or_else_with_carp(byea.insn_ea, 0x35E1FF)  # "banana"
                set_color_code_or_else_with_carp(ea, 0x30E1F0)  # "dandelion"
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
            set_color_code_or_else_with_carp(ea, 0xD6EAF0)  # "eggshell"
            refname = get_refname(ea)
            cmt = f"Processing env. var. func.: '{refname}'"
            mark_position(ea, cmt)
            print(f"{ea:#x} aka {refname} is interesting, {len(impcalls)} imports called:")
            for call in impcalls:
                disasm = idc.generate_disasm_line(call, 0)
                print(f"{call:#x} -> {disasm}")
    print(60 * "=")
    for varname in sorted(env_varnames.keys()):
        var_ea = env_varnames[varname]
        print(f"{var_ea:#x}: {varname}")


linkexe_hdr = """\
enum TOOL_TYPE
{
  ttHelper = 0,
  ttCvtCIL = 1,
  ttDumper = 2,
  ttEditor = 3,
  ttPushThunkObjGenerator = 4,
  ttLibraryManager = 5,
  ttLinker = 6,
};

struct calltype
{
  LPCWSTR ToolName;
  LPCWSTR ExecutableName;
  LPCWSTR ParamName;
  uint ParamNameLength;
  TOOL_TYPE ToolType;
  int (__cdecl *MainFunc)(int argc, wchar_t** argv);
};
"""


def process_calltypes(ea: int, arrsize: int, elemsize: int, typestr: str):
    sid = ida_struct.get_struc_id(typestr)
    if sid in {-1}:
        print(f"WARNING: failed to retrieve struct ID for {typestr}")
    else:
        mmbX, mmb0 = None, None
        struc = ida_struct.get_struc(sid)
        if struc is not None:
            mmb0 = struc.get_member(0)
            mmbX = struc.get_last_member()
        assert mmb0 is not None, "mmb0 turned out as None"
        assert mmbX is not None, "mmbX turned out as None"
        assert mmb0.get_size() in {8}, "Currently only supporting 64-bit"
        for idx in range(0, arrsize):
            ea_name = ea + (idx * elemsize) + mmb0.get_soff()
            ea_func = ea_name + mmbX.get_soff()
            ea_strname = idc.get_qword(ea_name)  # string pointer
            ea_mainfunc = idc.get_qword(ea_func)  # function pointer
            strlit = get_strlit(ea_strname)
            if strlit is not None:
                # print(f"{ea_name:#x}: at {idx=} {ea_func:#x} -> {strlit}")
                func = ida_funcs.get_func(ea_mainfunc)
                ida_funcs.set_func_cmt(func, f"{strlit}: calltype -> {ea_name:#x}", False)
                set_color_code_or_else_with_carp(ea_mainfunc, 0xF0FAFF)  # floral white
                ida_xref.add_dref(ea_mainfunc, ea_name, ida_xref.XREF_USER | ida_xref.dr_I)
                mark_position(ea_mainfunc, f"Main function: {strlit}")


def fixup_tooltype(ea: int):
    arrsize = 8
    typestr = "calltype"
    elemsize = sizeof(typestr) or 0
    assert elemsize == 0x28, f"sizeof({typestr}) does not match expectation, got {elemsize=}"  # perhaps later 32-bit?
    retval = idc.make_array(ea, arrsize)
    if not retval:
        return retval, f"ERROR: Failed to define array [{arrsize}] at {ea:#x}!"
    cmt = "Tool types table (lib, edit, link ...)"
    idc.set_cmt(ea, cmt, True)
    set_color_code_or_else_with_carp(ea, 0xF0FAFF)  # floral white
    mark_position(ea, cmt)
    process_calltypes(ea, arrsize, elemsize, typestr)
    return retval, f"INFO: Created array at {ea:#x}!"


def fixup_dbflags(ea: int):
    arrsize = 73
    retval = idc.make_array(ea, arrsize)
    if not retval:
        return retval, f"ERROR: Failed to define array [{arrsize}] at {ea:#x}!"
    return retval, f"INFO: Created array at {ea:#x}!"


def fixup_szphase(ea: int):
    idc.set_cmt(ea, "current phase of linking/processing", True)
    return True, None


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
        "?CvtCilUsage@@YAXXZ": ("CvtCilUsage", None),
        "?DumperUsage@@YAXXZ": ("DumperUsage", None),
        "?LibrarianUsage@@YAXXZ": ("LibrarianUsage", None),
        "?LinkerUsage@@YAXXZ": ("LinkerUsage", None),
        "?EmitHelp@@YAXII@Z": ("EmitHelp", "void {newname}(unsigned int toolmsg, unsigned int helpmsg);"),
        "?Message@@YAXIZZ": ("Message", "void {newname}(unsigned int, ...);"),
        "?ProcessCommandFile@@YAXPEBG@Z": ("ProcessCommandFile", "void {newname}(LPCWSTR name);"),
        "?link_wfsopen@@YAPEAU_iobuf@@PEBG0H@Z": ("link_wfsopen", "FILE* {newname}(LPCWSTR filename, LPCWSTR mode, int shflag);"),
        "?link_ftell@@YAJPEAU_iobuf@@@Z": ("link_ftell", "off_t {newname}(FILE* stream);"),
        "?link_fseek@@YAHPEAU_iobuf@@JH@Z": ("link_fseek", "int {newname}(FILE* stream, off_t offset, int origin);"),
        "?link_fclose@@YAHPEAU_iobuf@@@Z": ("link_fclose", "int {newname}(FILE* stream);"),
        "?link_fwprintf@@YAHPEAU_iobuf@@PEBGZZ": ("link_fwprintf", "int {newname}(FILE* stream, wchar_t const *format, ...);"),
        "?link_vfwprintf@@YAHPEAU_iobuf@@PEBGPEAD@Z": ("link_vfwprintf", "int {newname}(FILE* stream, wchar_t const *format, va_list argptr);"),
        "?link_fread@@YA_KPEAX_K1PEAU_iobuf@@@Z": ("link_fread", "size_t {newname}(void *buffer, size_t size, size_t count, FILE *stream);"),
        "?SzTrimFile@@YAPEADPEBD@Z": ("SzTrimFile", "char* {newname}(char const* string1);"),
        "?SzDupWsz@@YAPEADPEBG@Z": ("SzDupWsz", "char* {newname}(LPCWSTR lpWideCharStr);"),
        "?SHA1Update@SHA1Hash@@AEAAXPEAUSHA1_CTX@@PEBEK@Z": (
            "SHA1Hash__SHA1Update",
            "void {newname}(SHA1Hash *__hidden this, struct SHA1_CTX *, uchar const* buf, ulong buflen);",
        ),
        "?OutputInit@@YAXXZ": ("OutputInit", "void {newname}();"),  # use to find InfoStream and StdoutStream globals
        "FIsConsole": ("FIsConsole", "bool {newname}(FILE *stream);"),
        "?ControlCHandler@@YAHK@Z": ("ControlCHandler", "BOOL {newname}(DWORD CtrlType);"),
        "?EndEnmUndefExtNonWeak@@YAXPEAVENM_UNDEF_EXT@@@Z": (
            "EndEnmUndefExtNonWeak",
            "void {newname}(LPCWSTR expression, LPCWSTR function, LPCWSTR file,uint line, uintptr_t);",
        ),
        "?ProcessWildCards@@YAXPEBG@Z": ("ProcessWildCards", "void {newname}(LPCWSTR FileArgument);"),
        "?ProcessArgument@@YAXPEAG_N11@Z": ("ProcessArgument", "void {newname}(LPWSTR Argument, bool, bool, bool);"),
        "?_find@@YAPEAGPEBG@Z": ("_find", "LPWSTR _find(LPCWSTR lpFileName);"),
        "?PrintLogo@@YAXXZ": ("PrintLogo", "void PrintLogo(void);"),
        "?ProcessEditorSwitches@@YAXHPEBGHK_N1@Z": ("ProcessEditorSwitches", "void {newname}(int, LPCWSTR, int, unsigned int, bool, bool);"),
        "?ParseSymbol@@YAXPEBG0_N@Z": ("ParseSymbol", "void {newname}(LPWSTR Source, LPCWSTR, bool);"),
        "?FileMove@@YAXPEBG0@Z": ("FileMove", "void {newname}(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);"),
        "?FileHardClose@@YAXPEBG_N@Z": ("FileHardClose", "void {newname}(LPCWSTR lpFileName)"),
        "?FileRemove@@YA_NPEBG@Z": ("FileRemove", "bool {newname}(LPCWSTR FileName);"),
        "GetFilePos": ("GetFilePos", "DWORD {newname}(HANDLE hFile);"),
        "?CheckErrNo@@YAXXZ": ("CheckErrNo", "void {newname}();"),
        "?CheckHResult@@YA_NJ@Z": ("CheckHResult", "bool {newname}(HRESULT hr);"),
        "CheckHResultFailure": ("CheckHResultFailure", "void {newname}(HRESULT hr);"),
        "?InfoPrintf@@YAHPEBGZZ": ("InfoPrintf", "int {newname}(wchar_t const *format, ...);"),
        "?InfoVprintf@@YAHPEBGPEAD@Z": (
            "InfoVprintf",
            "int {newname}(wchar_t const *format, va_list argptr);",
        ),  # use to find szOutputRedirectionString and InfoStream globals
        "ExpandOutputString": ("ExpandOutputString", "int {newname}(wchar_t const *format, va_list argptr);"),
        "?StdOutVprintf@@YAHPEBGPEAD@Z": ("StdOutVprintf", "int {newname}(wchar_t const *format, va_list argptr);"),  # use to find fIsOutputRedirected globals
        "?InfoClose@@YAHXZ": ("InfoClose", "int {newname}(void);"),
        "?DisplayFatal@@YAXPEBG_KW4MSGTYPE@@_NIPEAD@Z": (
            "DisplayFatal",
            "void __noreturn {newname}(wchar_t const *format, __int64 unknown2, unsigned int unknown3, bool unknown4, unsigned int msgid, va_list argptr);",
        ),
        "?DisplayMessage@@YAXPEBG_KW4MSGTYPE@@IPEAD@Z": (
            "DisplayMessage",
            "void {newname}(const wchar_t *format, __int64 unknown2, unsigned int unknown3, unsigned int msgid, va_list argptr);",
        ),
        "?DisplayWarning@@YAXPEBG_KIPEAD@Z": ("DisplayWarning", "void {newname}(const wchar_t *format, __int64 unknown2, unsigned int msgid, va_list argptr);"),
        "?Fatal@@YAXPEBGIZZ": (
            "Fatal",
            "void __noreturn {newname}(wchar_t const *format, unsigned int msgid, ...);",
        ),  # -> process to comment which message ID is being set (and make the number operand decimal) [EDX]
        "?Fatal@CON@@QEBAXIZZ": (None, "void __noreturn CON::Fatal(CON *__hidden this, unsigned int msgid, ...);"),
        "?Warning@@YAXPEBGIZZ": (None, None),  # [EDX]
        "?WarningLine@@YAXPEBG_KIZZ": ("WarningLine", "void {newname}(wchar_t const *format, __int64 unknown2, unsigned int msgid, ...);"),
        "EditorFatal": ("EditorFatal", "void __noreturn EditorFatal(wchar_t *format, unsigned int msgid, ...);"),
        "?DisableWarning@@YAXI@Z": ("DisableWarning", "void {newname}(unsigned int msgid)"),
        "?FIgnoreWarning@@YA_NI@Z": ("FIgnoreWarning", "bool FIgnoreWarning(unsigned int msgid);"),
        "?FWarningAsError@@YA_NI@Z": ("FWarningAsError", "bool FWarningAsError(unsigned int msgid);"),  # cs:?fWarningIsError@@3_NA
        # Imports
        "__imp_scalable_malloc": ("__imp_scalable_malloc", "void* scalable_malloc(size_t size);"),
        "__imp_scalable_realloc": ("__imp_scalable_realloc", "void* scalable_realloc(void* memblock, size_t size);"),
        "__imp_scalable_free": ("__imp_scalable_free", "void scalable_free(void* memblock);"),
        "__imp_scalable_aligned_malloc": ("__imp_scalable_aligned_malloc", "void* scalable_aligned_malloc(size_t size, size_t alignment);"),
        "__imp_scalable_aligned_realloc": ("__imp_scalable_aligned_realloc", "void* scalable_aligned_realloc(void* memblock, size_t size, size_t alignment);"),
        "__imp_scalable_aligned_free": ("__imp_scalable_aligned_free", "void scalable_aligned_free(void* memblock);"),
        # Data
        "?Dbflags@@3PADA": ("Dbflags", "bool Dbflags[73];", fixup_dbflags),
        "?ToolName@@3PEBGEB": ("ToolName", "LPWSTR ToolName;"),
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
        "?Tool@@3W4TOOL_TYPE@@A": ("Tool", "TOOL_TYPE {newname};"),
        "?ToolType@@3PAUcalltype@@A": ("ToolType", "calltype {newname}[8];", fixup_tooltype),
        "?fCtrlCSignal@@3KA": ("fCtrlCSignal", "uint {newname};"),
        "?szPhase@@3PEBGEB": ("szPhase", "LPCWSTR {newname};", fixup_szphase),  # TODO: resolve all assignments to comments
        # ?rgpfi@BufIOPrivate@@3PEAPEAUFI@@EA -> table of file "descriptors", the index is used as "file number"
        # "Library" functions
        "?strdup_TCE@@YAPEADPEBD@Z": ("strdup_TCE", "char* {newname}(char const* strSource);", None, True),
        "?strdup_TCE@@YAXPEBDPEAPEADPEA_K@Z": (None, "void strdup_TCE(char const* Src, char ** Duplicated, size_t * allocated);", None, True),
        "strcmp_0": ("strcmp_0", "int {newname}(char const *str1, char const *str2);", None, True),
        "?wcschr@@YAPEAGPEAGG@Z": ("wcschr", "wchar_t * {newname}(const wchar_t *str, wchar_t ch);", None, True),
        "wcsrchr_0": (None, "wchar_t * {newname}(const wchar_t *str, wchar_t ch);", None, True),
        "wcscmp_0": (None, "int __cdecl {newname}(const wchar_t *str1, const wchar_t *str2);", None, True),
        "swscanf_s": (None, "int {newname}(wchar_t const*const buffer, wchar_t const*const format, ...);", None, True),
        "swprintf_s": (None, "int {newname}(wchar_t *const Buffer, const size_t BufferCount, const wchar_t *const Format, ...);", None, True),
        "?memcpy_avx@@YAPEBXPEBX0_K@Z": ("memcpy_avx", "void const* {newname}(void * dst, void const* src, size_t count);", None, True),
        "strncmp_avx": ("strncmp_avx", "int {newname}(char const* str1, char const* str2, size_t count);", None, True),
    },
}


def retype_single(oldname: str, newname: Optional[str], rule: tuple, tinfo_flags=idc.TINFO_DEFINITE) -> bool:
    if len(rule) in {1}:  # normalize
        rule = (rule[0], None, None, None)  # fmt: skip
    elif len(rule) in {2}:  # normalize
        rule = (rule[0], rule[1], None, None)  # fmt: skip
    elif len(rule) in {3}:  # normalize
        rule = (rule[0], rule[1], rule[2], None)  # fmt: skip
    assert len(rule) == 4, f"Unexpected size: {len(rule)=} (for {oldname=}/{newname=}/{rule=})"
    (ea, name), newtype, raw_fixup, _ = rule
    if newname is None:
        newname = oldname
    if newtype is None:
        return False, None, f"INFO: no new type for {oldname}/{newname}"
    newtype = newtype.format(**locals())
    tp = idc.parse_decl(newtype, 0)
    if tp is None:
        return False, None, f"ERROR: Could not parse '{newname}' function type {newtype=}"
    if not idc.apply_type(ea, tp, tinfo_flags):
        return False, None, f"{ea:#x}: ERROR: Failed to apply function type => {newtype}"
    fixup = partial(raw_fixup, ea) if callable(raw_fixup) else None  # specialize to the ea
    return True, fixup, f"{ea:#x}: INFO: Re-typed {name} => {newtype}"


def rename_single(oldname: str, newname: Optional[str], rule: tuple) -> bool:
    if len(rule) in {1}:  # normalize
        rule = (rule[0], None, None, None)  # fmt: skip
    elif len(rule) in {2}:  # normalize
        rule = (rule[0], rule[1], None, None)  # fmt: skip
    elif len(rule) in {3}:  # normalize
        rule = (rule[0], rule[1], rule[2], None)  # fmt: skip
    assert len(rule) == 4, f"Unexpected size: {len(rule)=}"
    (ea, _), _, _, _ = rule
    if newname is None or newname == oldname:
        return False, f"INFO: no new name for {oldname}"
    if not idc.set_name(ea, newname):
        return False, f"{ea:#x}: ERROR: Failed to rename {oldname=} to {newname=}"
    return True, f"{ea:#x}: INFO: Renamed {oldname=} to {newname=}" if oldname != newname else None


def rename_and_retype(renames: dict, verbose: bool = False):
    rfname = idc.get_root_filename()  # get_input_file_path() for IDB _path_
    assert rfname, "Could not retrieve name of the file used to create the IDB"
    if rfname not in renames:
        print(f"WARNING: Could not find '{rfname}' as top-level key in the renaming rules")
        return
    if rfname in {"link.exe"}:  # TODO: move this out and make more data-driven
        errs = ida_typeinf.parse_decls(None, linkexe_hdr, None, ida_typeinf.HTI_DCL)
        if errs in {0}:
            print(f"INFO: no errors applying C types for '{rfname}'")
        else:
            print(f"WARNING: {errs} errors applying C types for '{rfname}'")
    print(f"INFO: applying renaming and re-typing rules for '{rfname}'")

    all_rules = set(renames[rfname].keys())
    rules = renames[rfname]

    # Determine the items that were already renamed and those we need to rename
    renames = {
        (oldnm, rules[oldnm][0]): (nm, *rules[oldnm][1:])
        for nm in idautils.Names()
        for oldnm in rules
        if oldnm == nm[1] and oldnm != rules[oldnm][0] and rules[oldnm][0] is not None
    }
    renamed = {(oldnm, rules[oldnm][0]): (nm, *rules[oldnm][1:]) for nm in idautils.Names() for oldnm in rules if rules[oldnm][0] == nm[1]}

    rule_count = len(rules)
    accounted_for_rule_count = len(renames) + len(renamed)

    missing = all_rules - set([k[0] for k in renames.keys()]) - set([k[0] for k in renamed.keys()])
    for not_really in [x for nm in idautils.Names() for x in missing if x == nm[1]]:
        missing.remove(not_really)
    print(f"INFO: {len(renames)} items to rename, {len(renamed)} already renamed, {len(missing)} missing from IDB")

    if verbose and len(missing):
        print(f"WARNING: {rule_count=} <> {accounted_for_rule_count=} ({len(rules)=})")
        for item in sorted(missing):
            print(f"WARNING: missing '{item}'")

    if renames:
        print(50 * "=", "[RENAMES]", 10 * "=")
        for (oldname, newname), rule in renames.items():
            success, fixup, msg = retype_single(oldname, newname, rule)
            if (verbose and msg) or (not success and msg):
                print(msg)
            success, msg = rename_single(oldname, newname, rule)
            if (verbose and msg) or (not success and msg):
                print(msg)
            if callable(fixup):
                success, msg = fixup()
                if (verbose and msg) or (not success and msg):
                    print(msg)

    if renamed:
        print(50 * "=", "[RENAMED]", 10 * "=")
        for (oldname, newname), rule in renamed.items():
            success, fixup, msg = retype_single(oldname, newname, rule)
            if (verbose and msg) or (not success and msg):
                print(msg)
            if callable(fixup):
                success, msg = fixup()
                if (verbose and msg) or (not success and msg):
                    print(msg)

    shown_libfuncs_banner = False
    for oldname, rule in rules.items():
        if len(rule) > 3 and rule[3]:
            names = set([oldname])
            if rule[0] is not None:
                names.add(rule[0])
            match = set([nm[0] for nm in idautils.Names() for match in names if nm[1] in names])
            assert len(match) == 1, f"Expected exactly one ({len(match)=}) match for {oldname=}: {match}"
            ea = list(match)[0]
            if add_func_flags(ea, idc.FUNC_LIB):
                if not shown_libfuncs_banner:
                    print(50 * "=", "[LIBFUNCS]", 10 * "=")
                    shown_libfuncs_banner = True
                print(f"Marked {oldname} at {ea:#x} as library function")


def mark_lib_functions():
    libfunc_lambdas = [
        lambda x: x.startswith("std::vector<std::wstring>::"),
        lambda x: x.startswith("std::vector<bool>::"),
        lambda x: x.startswith("std::string::"),
        lambda x: x.startswith("std::filesystem::"),
        lambda x: x.startswith("std::basic_string<unsigned short,"),
        lambda x: x.startswith("std::basic_streambuf<unsigned short,"),
        lambda x: x.startswith("std::basic_istream<unsigned short,"),
        lambda x: x.startswith("std::bad_cast::"),
        lambda x: x.startswith("std::use_facet<"),
        lambda x: x.startswith("std::vector<char,"),
        lambda x: x.startswith("std::vector<ulong>::"),
        lambda x: x.startswith("std::vector<unsigned __int64>::"),
        lambda x: x.startswith("std::error_category::"),
        lambda x: x.startswith("std::basic_string_view<unsigned short,"),
        lambda x: x.startswith("std::basic_stringbuf<unsigned short,"),
        lambda x: x == "??$swprintf_s@$0CAA@@@YAHAEAY0CAA@GPEBGZZ",
        lambda x: x == "_vswprintf_s_l",
        lambda x: x == "memset_zero_avx",
        lambda x: x == "memcpy_s",
        lambda x: x == "initialize_legacy_wide_specifiers",
        lambda x: x == "fwprintf",
        lambda x: x == "_cprintf",
        lambda x: x == "_vcprintf_l",
        lambda x: x == "_vfprintf_l",
        lambda x: x == "_vfwprintf_l",
        lambda x: x == "_vsnprintf_s_l",
        lambda x: x == "_vsnwprintf_s_l",
        lambda x: x == "_vswprintf_s_l",
        lambda x: x == "_snwprintf_s",
        lambda x: x == "_snprintf_s",
        lambda x: x.startswith("__scrt_"),
        lambda x: x == "__delayLoadHelper2",
    ]
    counter = 0
    for ea, name in idautils.Names():
        for check in libfunc_lambdas:
            demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
            if check(name) or check(demangled or ""):
                if add_func_flags(ea, idc.FUNC_LIB):
                    if demangled:
                        print(f"INFO: marked lib function at {ea:#x} -> {demangled} ({name})")
                    else:
                        print(f"INFO: marked lib function at {ea:#x} -> {name}")
                    counter += 1
    if counter:
        print(f"INFO: marked {counter} library functions")


def color_lambdas():
    lmbdre = re.compile(r"_lambda_[0-9a-f]{32}")
    counter = 0
    for ea, name in idautils.Names():
        if lmbdre.search(name):
            # demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
            # if demangled:
            # print(f"INFO: lambda-related name at {ea:#x} -> {demangled} ({name})")
            # else:
            # print(f"INFO: lambda-related name at {ea:#x} -> {name}")
            if set_color_code_or_else_with_carp(ea, 0xFAE6E6):  # lavender (bright)
                counter += 1
    if counter:
        print(f"INFO: colored {counter} lambda-related names")


def color_initializers():
    counter = 0
    for ea, name in idautils.Names():
        if "_dynamic_initializer_for" in name:
            if set_color_code_or_else_with_carp(ea, 0x98FF98, 0xADDFAD):  # mint green / moss green
                counter += 1
    if counter:
        print(f"INFO: colored {counter} initializer-related names")


def color_dtors():
    counter = 0
    for ea, name in idautils.Names():
        if "_dynamic_atexit_destructor_for" in name:
            if set_color_code_or_else_with_carp(ea, 0x5E6FFE, 0x6699FF):  # bittersweet / atomic tangerine
                counter += 1
    if counter:
        print(f"INFO: colored {counter} atexit-dtor-related names")


def color_delayloads():
    counter = 0
    for ea, name in idautils.Names():
        if "__imp_load_" in name:
            if set_color_code_or_else_with_carp(ea, 0x2258E2):  # flame
                counter += 1
    if counter:
        print(f"INFO: colored {counter} delayload-related names")


def mark_and_color_usagefuncs():
    counter = 0
    for ea, name in idautils.Names():
        if "Usage" in name:
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_code(flags):
                if set_color_code_or_else_with_carp(ea, 0xE6F0FA):  # linen
                    counter += 1
                mark_position(ea, f"Usage function: {name}")
    if counter:
        print(f"INFO: colored {counter} usage function names")


def main():
    clear_output_console()
    rename_and_retype(toolchain_renames)
    mark_lib_functions()
    color_lambdas()
    color_initializers()
    color_dtors()
    color_delayloads()
    mark_and_color_usagefuncs()
    detect_environment_variables()


if __name__ == "__main__":
    main()

# idaapi.refresh_idaview_anyway()
# rsrc_string_format from custom_data_types_and_formats.py may also come in handy for some functions
