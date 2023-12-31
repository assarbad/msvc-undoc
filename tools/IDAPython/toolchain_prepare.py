import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_idc
import ida_name
import ida_struct
import ida_typeinf
import ida_xref
import idc
import re
import yaml
from collections import namedtuple
from functools import partial
from pathlib import Path
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


rfname: str = None  # global root file name of IDB
glblinfo = idaapi.get_inf_structure()
slotidx: int = 1023
marked_positions_ea: set = {}


def set_color(ea: int, what: int, color: int) -> Tuple[Optional[bool], Optional[str]]:
    """\
        Colors a given EA and returns a tuple of a bool (or None) for success failure
        and a hopefully meaningful status message
    """
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
    """\
        Adds flags to a function given by its EA

        Returns True in case of success. False in case of failure and None in case nothing had to be done (flags already set)
    """
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
    """\
        Applies a bookmark/mark comment to a given EA
    """
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


def get_strlit(ea: int) -> Optional[str]:
    """\
        Returns the string contents a given string literal has or None if no string literal
    """
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_strlit(flags):
        strtype = idc.get_str_type(ea)
        strlit = idc.get_strlit_contents(ea, -1, strtype)
        if strlit is not None:
            strlit = strlit.decode("utf-8")
            return strlit
    return None


def sizeof(typestr: str) -> int:
    """\
        Determines the size of a known type
    """
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


c1_and_c1xx_dll_hdr = """\
struct c1switch_t
{
  const char *Name;
  void *pValueOrFunc;
  bool field_10;
  bool field_11;
  bool field_12;
  bool field_13;
  int field_14;
};
"""


per_module_typedefs = {
    "c1.dll": c1_and_c1xx_dll_hdr,
    "c1xx.dll": c1_and_c1xx_dll_hdr,
    "c2.dll": """\
struct c2switch_t
{
  wchar_t *const Name;
  void *pValue;
  long long field_10;
  int field_18;
  int field_1C;
};
""",
    "cl.exe": """\
struct early_switch_t
{
  void *SwitchName;
  void *SwitchFlag;
  long long SwitchUnknown;
};

struct late_switch_t
{
  void *SwitchName;
  long long SwitchType;
  void* VarOrFunc;
};

struct form_t
{
  void *field_0;
  void *field_8;
  void *field_10;
  void *field_18;
  void *field_20;
  void *field_28;
  long long field_30;
};

struct combo_t
{
  void *field_0;
  void *field_8;
  void *field_10;
};
""",
    "link.exe": """\
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
""",
}


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


def make_array_helper(arrsize: int, ea: int):
    retval = idc.make_array(ea, arrsize)
    if not retval:
        name = ida_name.get_name(ea)
        errstr = f"ERROR: Failed to define array [{arrsize}] at {ea:#x}!"
        if name:
            errstr = f"ERROR: Failed to define array [{arrsize}] at {ea:#x} ({name})!"
        return retval, errstr
    return retval, f"INFO: Created array at {ea:#x}!"


def fixup_szphase(ea: int):
    idc.set_cmt(ea, "current phase of linking/processing", True)
    return True, None


toolchain_renames = {
    "c1.dll": {
        "?crack_cmd@@YAHPEBUcmdtab@@PEADP6APEADXZH@Z": (
            "crack_cmd",
            "void * {newname}(const struct cmdtab *table, char *nxtwrd, char *(*callback)(void));",
        ),
        "?nextword@@YAPEAGXZ": ("nextword", "char *{newname}(void);"),
        "?init_main1@@YAXHPEAPEAD@Z": ("init_main1", "void {newname}(int argc, char** argv);"),
        "?main_compile@@YAHXZ": ("main_compile", "int {newname}(void);"),
        "?CallMain@@YAHHPEAPEAD@Z": ("CallMain", "int {newname}(int argc, char** argv);"),
        "Trap_main_compile": ("Trap_main_compile", "int {newname}();"),
        "?DummyFlag@@3_NA": ("DummyFlag", "bool {newname};"),
        "?DummyString@@3PEBDEB": ("DummyString", "char* {newname};"),
        "?DummyNumber@@3HA": ("DummyNumber", "int {newname};"),
        "?Cmd_WarnVersion@@3W4ClVersion@@A": ("Cmd_WarnVersion",),
        "?warning_introduced_in_current_release@@YA_NW4WarningNumber@@@Z": ("warning_introduced_in_current_release", "bool {newname}(enum WarningNumber);"),
        "?InitSpecialWarnings@@YAXXZ": ("InitSpecialWarnings", "void {newname}();"),  # use this and the above to set warningbyrel_t array
    },
    "c1xx.dll": {
        "?crack_cmd@@YAHPEBUcmdtab@@PEADP6APEADXZH@Z": (
            "crack_cmd",
            "void * {newname}(const struct cmdtab *table, char *nxtwrd, char *(*callback)(void));",
        ),
        "?nextword@@YAPEAGXZ": ("nextword", "char *{newname}(void);"),
        "?init_main1@@YAXHPEAPEAD@Z": ("init_main1", "void {newname}(int argc, char** argv);"),
        "?main_compile@@YAHXZ": ("main_compile", "int {newname}(void);"),
        "?CallMain@@YAHHPEAPEAD@Z": ("CallMain", "int {newname}(int argc, char** argv);"),
        "Trap_main_compile": ("Trap_main_compile", "int {newname}();"),
        "?DummyFlag@@3_NA": ("DummyFlag", "bool {newname};"),
        "?DummyString@@3PEBDEB": ("DummyString", "char* {newname};"),
        "?DummyNumber@@3HA": ("DummyNumber", "int {newname};"),
        "?Cmd_WarnVersion@@3W4ClVersion@@A": ("Cmd_WarnVersion",),
        "?warning_introduced_in_current_release@@YA_NW4WarningNumber@@@Z": ("warning_introduced_in_current_release", "bool {newname}(enum WarningNumber);"),
        "?InitSpecialWarnings@@YAXXZ": ("InitSpecialWarnings", "void {newname}();"),  # use this and the above to set warningbyrel_t array
    },
    "c2.dll": {
        "?crack_cmd@@YAHPEBUcmdtab@@PEAGP6APEAGXZH@Z": (
            "crack_cmd",
            "void * {newname}(const struct cmdtab *table, wchar_t *nxtwrd, wchar_t *(*callback)(void));",
        ),
        "?nextword@@YAPEAGXZ": ("nextword", "wchar_t *{newname}(void);"),
        "?ProcessSwitches@@YAXXZ": ("ProcessSwitches", "void {newname}(void);"),
        "?MainInit@@YAXHPEAPEAG@Z": ("MainInit", "int {newname}(int argc, wchar_t **argv);"),
        # "?MainMod@@3UtagMOD@@A": ("MainMod", "tagMOD {newname};"),
        "?COMPILER_VERSION_W@@3QBGB": ("COMPILER_VERSION_W", "wchar_t const* const {newname};"),
        # substr
    },
    "cl.exe": {
        "?LOGO@@YAXH@Z": ("LOGO", "void {newname}(int);"),
        "?MP_is_server@@YAHXZ": ("MP_is_server", "BOOL {newname}();"),
        "?MP_main@@YAXXZ": ("MP_main", "void {newname}();"),
        "?MP_server_main@@YAXXZ": ("MP_server_main", "void {newname}();"),
        "?hasAnalyze@@YA_NXZ": ("hasAnalyze", "bool {newname}();"),
        "?sztoszv@@YAPEAPEAGPEAGH@Z": (
            "sztoszv",
            "wchar_t** {newname}(wchar_t*, int);",
        ),  # use to convert env variable command line arguments to argv-like list
        "argcount": ("argcount", "size_t {newname}(wchar_t** argv);"),
        "main": ("wmain", "int {newname}(int argc, wchar_t** argv);"),
        # "?cc_switches@@YAXPEAUcontext_t@@H@Z": (),
        # "early_switch_scan" # -> detect early_switches
        # ?handlematch@@YAHPEBQEBGHPEAHH@Z
        "?newflag@@YAPEAUflag_t@@PEBG00H@Z": (
            "newflag",
            "struct flag_t * {newname}(const wchar_t *szFlag1, const wchar_t *szFlag2, const wchar_t *szFlag3, uint16_t unknown_flag_flag);",
        ),
        "?execute@@YAHW4driver_phases@@PEAUpassinfo_t@@PEBG2PEAPEAG@Z": (
            "execute",
            "__int64 {newname}(int a1, struct passinfo_t *passinfo, const wchar_t *lpszPassDllName, const wchar_t *a4, wchar_t **argv);",
        ),
        "?Dargs@@YAPEAUflag_t@@PEBQEBGHPEAH@Z": ("Dargs", "struct flag_t * {newname}(wchar_t **argv, int a2, int *argidx);"),
        "?flagmatch@@YAHPEAUflag_t@@0@Z": ("flagmatch", "bool {newname}(struct flag_t *flag1, struct flag_t *flag2);"),
        "?expand@@YAPEAUflag_t@@PEAGPEAU1@@Z": ("expand", "struct flag_t * {newname}(wchar_t *pattern, struct flag_t *a2);"),
        "?prefast_init@@YAXXZ": ("prefast_init", "void {newname}();"),
        "?execute_scrutinized_c1xx@@YAHPEAUcontext_t@@P6AH0@Z@Z": (
            "execute_scrutinized_c1xx",
            "BOOL {newname}(struct context_t *context, int (*callback)(struct context_t *));",
        ),
        "?adjustPchName@@YAPEBGPEBGPEAGH@Z": ("adjustPchName", "wchar_t *__fastcall {newname}(const wchar_t *a1, wchar_t *a2);"),
        "?appendflag@@YAPEAUflag_t@@PEAPEAU1@PEAU1@@Z": ("appendflag", "struct flag_t * {newname}(struct flag_t **existing_flag, struct flag_t *newflag);"),
        "?deactivate_passes@@YAXPEAUflag_t@@@Z": ("deactivate_passes", "void {newname}(struct flag_t *flag);"),
        "?link_dll@@YAXPEAUflag_t@@@Z": ("link_dll", "void link_dll(struct flag_t *newflag);"),
        # Data
        "?AllowCwithCLR@@3HA": ("AllowCwithCLR", "BOOL {newname};"),
        "?AnalyzePathFlag@@3HA": ("AnalyzePathFlag", "BOOL {newname};"),
        "?C1astPathFlag@@3HA": ("C1astPathFlag", "BOOL {newname};"),
        "?C1xxastPathFlag@@3HA": ("C1xxastPathFlag", "BOOL {newname};"),
        "?CaptureReproDir@@3PEAGEA": ("CaptureReproDir", "wchar_t* {newname};"),
        "?ClrNetCore@@3HA": ("ClrNetCore", "BOOL {newname};"),
        "?CluiPath@@3PAGA": ("CluiPath", "wchar_t {newname}[0x400];", partial(make_array_helper, 0x400)),
        "?CluiPathFlag@@3HA": ("CluiPathFlag", "BOOL {newname};"),
        "?Cmd_IsFpSpecified@@3HA": ("Cmd_IsFpSpecified", "BOOL {newname};"),
        "?Cmd_IsYuSpecified@@3HA": ("Cmd_IsYuSpecified", "BOOL {newname};"),
        "?Cmd_Nopft@@3HA": ("Cmd_Nopft", "BOOL {newname};"),
        "?Cmd_OldPrefast@@3HA": ("Cmd_OldPrefast", "BOOL {newname};"),
        "?Cmd_PchBaseAddress@@3HA": ("Cmd_PchBaseAddress", "BOOL {newname};"),
        "?Cmd_PchFile@@3PEBGEB": ("Cmd_PchFile", "wchar_t* {newname};"),
        "?Cmd_PchFileBuffer@@3PAGA": ("Cmd_PchFileBuffer", "wchar_t {newname}[0x400];", partial(make_array_helper, 0x400)),
        "?Cmd_Prefast@@3HA": ("Cmd_Prefast", "BOOL {newname};"),
        "?Cmd_PrefastOnly@@3HA": ("Cmd_PrefastOnly", "BOOL {newname};"),
        "?Cmd_ScaleMemory@@3HA": ("Cmd_ScaleMemory", "BOOL {newname};"),
        "?Cmd_WinRT@@3HA": ("Cmd_WinRT", "BOOL {newname};"),
        "?Cmd_experimental_c11atomics@@3HA": ("Cmd_experimental_c11atomics", "BOOL {newname};"),
        "?Cmd_experimental_concepts@@3HA": ("Cmd_experimental_concepts", "BOOL {newname};"),
        "?Cmd_experimental_deterministic@@3HA": ("Cmd_experimental_deterministic", "BOOL {newname};"),
        "?Cmd_experimental_external@@3HA": ("Cmd_experimental_external", "BOOL {newname};"),
        "?Cmd_experimental_module@@3HA": ("Cmd_experimental_module", "BOOL {newname};"),
        "?Cmd_external_warning_level_seen@@3HA": ("Cmd_external_warning_level_seen", "BOOL {newname};"),
        "?Cmd_ifc_only@@3HA": ("Cmd_ifc_only", "BOOL {newname};"),
        "?Cmd_ifc_version@@3HA": ("Cmd_ifc_version", "BOOL {newname};"),
        "?Cmd_module_export_header_mode@@3HA": ("Cmd_module_export_header_mode", "BOOL {newname};"),
        "?Cmd_module_no_stdifc@@3HA": ("Cmd_module_no_stdifc", "BOOL {newname};"),
        "?Cmd_module_stdifc_dir_flag@@3HA": ("Cmd_module_stdifc_dir_flag", "BOOL {newname};"),
        "?Cmd_phase_out_yacc@@3HA": ("Cmd_phase_out_yacc", "BOOL {newname};"),
        "?Cmd_std_cpplatest@@3HA": ("Cmd_std_cpplatest", "BOOL {newname};"),
        "?ComPlusIL@@3HA": ("ComPlusIL", "BOOL {newname};"),
        "?CrtName@@3PEAGEA": ("CrtName", "wchar_t* {newname};"),
        "?DefaultsMarked@@3HA": ("DefaultsMarked", "BOOL {newname};"),
        "?DisablePathCanonicalization@@3HA": ("DisablePathCanonicalization", "BOOL {newname};"),
        "?DllFlg@@3HA": ("DllFlg", "BOOL {newname};"),
        "?DontTrapExceptions@@3HA": ("DontTrapExceptions", "BOOL {newname};"),
        "?DumpPCHInfo@@3HA": ("DumpPCHInfo", "BOOL {newname};"),
        "?DumpPassInfo@@3HA": ("DumpPassInfo", "BOOL {newname};"),
        "?EnableENC@@3HA": ("EnableENC", "BOOL {newname};"),  # ENC == Edit and Continue
        "?EnableTelemetrySwitchLog@@3_NA": ("EnableTelemetrySwitchLog", "bool {newname};"),
        "?EncEventName@@3PEAGEA": ("EncEventName", "LPCWSTR {newname};"),
        "?EndtimeQPC@@3T_LARGE_INTEGER@@A": ("EndtimeQPC", "LARGE_INTEGER {newname};"),
        "?Endtime_telemetry@@3T_LARGE_INTEGER@@A": ("Endtime_telemetry", "LARGE_INTEGER {newname};"),
        "?Exefilename@@3PEAGEA": ("Exefilename", "wchar_t* {newname};"),
        "?Help@@3HA": ("Help", "BOOL {newname};"),
        "?Hybrid_x86arm64@@3HA": ("Hybrid_x86arm64", "BOOL {newname};"),
        "?Hybrid_x86native@@3HA": ("Hybrid_x86native", "BOOL {newname};"),
        "?IdbFileName@@3PEAGEA": ("IdbFileName", "wchar_t* {newname};"),
        "?IncrementalCompile@@3HA": ("IncrementalCompile", "BOOL {newname};"),
        "?IntelliSense@@3HA": ("IntelliSense", "BOOL {newname};"),
        "?LDdFlg@@3HA": ("LDdFlg", "BOOL {newname};"),  # selects debug CRT
        "?MPAllowBatching@@3HA": ("MPAllowBatching", "BOOL {newname};"),
        "?MPDebug@@3HA": ("MPDebug", "BOOL {newname};"),
        "?MPLowPriority@@3HA": ("MPLowPriority", "BOOL {newname};"),
        "?MPParams@@3PEAGEA": ("MPParams", "wchar_t* {newname};"),
        "?MPSeen@@3HA": ("MPSeen", "BOOL {newname};"),
        "?MP_batching@@3HA": ("MP_batching", "BOOL {newname};"),
        "?Mapfile@@3HA": ("Mapfile", "BOOL {newname};"),
        "?Mapfilename@@3PEAGEA": ("Mapfilename", "wchar_t* {newname};"),
        "?MinimalRebuild@@3HA": ("MinimalRebuild", "BOOL {newname};"),
        "?MspftPath@@3PAGA": ("MspftPath", "wchar_t {newname}[0x400];", partial(make_array_helper, 0x400)),
        "?MspftPathFlag@@3HA": ("MspftPathFlag", "BOOL {newname};"),
        "?NativeCodeAnalysisPathFlag@@3HA": ("NativeCodeAnalysisPathFlag", "BOOL {newname};"),
        "?NoAssembly@@3HA": ("NoAssembly", "BOOL {newname};"),
        "?NoMinRebuildAnalysis@@3HA": ("NoMinRebuildAnalysis", "BOOL {newname};"),
        "?NoOverrideWarnings@@3HA": ("NoOverrideWarnings", "BOOL {newname};"),
        "?Nologo@@3HA": ("Nologo", "BOOL {newname};"),
        "?Nospawn@@3HA": ("Nospawn", "BOOL {newname};"),
        "?Object@@3PEAGEA": ("Object", "wchar_t* {newname};"),
        "?OpenMP@@3HA": ("OpenMP", "BOOL {newname};"),
        "?OptionsStrict@@3HA": ("OptionsStrict", "BOOL {newname};"),
        "?PdbName@@3PEAGEA": ("PdbName", "wchar_t* {newname};"),
        "?PdbNameLTCG@@3PEAGEA": ("PdbNameLTCG", "wchar_t* {newname};"),
        "?PreProcessorInvoked@@3HA": ("PreProcessorInvoked", "BOOL {newname};"),
        "?PrefastLogFileFlag@@3HA": ("PrefastLogFileFlag", "BOOL {newname};"),
        "?PrefastLogFilePath@@3PAGA": ("PrefastLogFilePath", "wchar_t {newname}[0x400];", partial(make_array_helper, 0x400)),
        "?Preprocess@@3HA": ("Preprocess", "BOOL {newname};"),
        "?PrintHResultOnFail@@3HA": ("PrintHResultOnFail", "BOOL {newname};"),
        "?PrintReproInfo@@3HA": ("PrintReproInfo", "BOOL {newname};"),
        "?ReallyEnableENC@@3HA": ("ReallyEnableENC", "BOOL {newname};"),
        "?Reproducable@@3HA": ("Reproducable", "BOOL {newname};"),
        "?RespEcho@@3HA": ("RespEcho", "BOOL {newname};"),
        "?Saw_AnalyzeLog@@3HA": ("Saw_AnalyzeLog", "BOOL {newname};"),
        "?Saw_E@@3HA": ("Saw_E", "BOOL {newname};"),
        "?Saw_EP@@3HA": ("Saw_EP", "BOOL {newname};"),
        "?Saw_Gm@@3HA": ("Saw_Gm", "BOOL {newname};"),
        "?Saw_Yc@@3HA": ("Saw_Yc", "BOOL {newname};"),
        "?Saw_showIncludes@@3HA": ("Saw_showIncludes", "BOOL {newname};"),
        "?SbrFileName@@3PEAGEA": ("SbrFileName", "wchar_t* {newname};"),
        "?SourceCount@@3HA": ("SourceCount", "int {newname};"),
        "?SourceList@@3HA": ("SourceList", "BOOL {newname};"),
        "?StarttimeQPC@@3T_LARGE_INTEGER@@A": ("StarttimeQPC", "LARGE_INTEGER {newname};"),
        "?Starttime_telmetry@@3T_LARGE_INTEGER@@A": ("Starttime_telemetry", "LARGE_INTEGER {newname};"),
        "?SystemInfo@CVirtualMemoryAllocator@@0U_SYSTEM_INFO@@A": ("CVirtualMemoryAllocator::SystemInfo", "SYSTEM_INFO {newname};"),
        "?TerminationCritSec@@3U_RTL_CRITICAL_SECTION@@A": ("TerminationCritSec", "RTL_CRITICAL_SECTION {newname};"),
        "?TimePlus@@3HA": ("TimePlus", "BOOL {newname};"),
        "?UseEdge@@3HA": ("UseEdge", "BOOL {newname};"),
        "?Verbose@@3HA": ("Verbose", "BOOL {newname};"),
        "?VersionNumber@@3PAGA": ("VersionNumber", "wchar_t {newname}[16];", partial(make_array_helper, 16)),
        "?WowA64@@3HA": ("WowA64", "BOOL {newname};"),
        "?XMLdocFileName@@3PEAGEA": ("XMLdocFileName", "wchar_t* {newname};"),
        "?ZXSeen@@3HA": ("ZXSeen", "BOOL {newname};"),
        "?fArchAVX2@@3HA": ("fArchAVX2", "BOOL {newname};"),
        "?fArchAVX@@3HA": ("fArchAVX", "BOOL {newname};"),
        "?fAwait@@3HA": ("fAwait", "BOOL {newname};"),
        "?fAwaitHeapElide@@3HA": ("fAwaitHeapElide", "BOOL {newname};"),
        "?fForceZ7@@3HA": ("fForceZ7", "BOOL {newname};"),
        "?fKernel@@3HA": ("fKernel", "BOOL {newname};"),
        "?fMPX@@3HA": ("fMPX", "BOOL {newname};"),
        "?fNoDeprecationWarnings@@3HA": ("fNoDeprecationWarnings", "BOOL {newname};"),
        "?g_hCryptProv@@3_KA": ("g_hCryptProv", "HCRYPTPROV {newname};"),
        "?g_hMutex@@3PEAXEA": ("g_hMutex", "HANDLE {newname};"),
        "?hUIModule@@3PEAUHINSTANCE__@@EA": ("hUIModule", "HMODULE {newname};"),
        "?is_server_run@@3HA": ("is_server_run", "BOOL {newname};"),
        "?pPCHBaseAddress@@3PEAXEA": ("pPCHBaseAddress", "void* {newname};"),
        "?remaining_passes@@3JA": ("remaining_passes", "long {newname};"),
        "?saved_Cmd_ScaleMemory@@3HA": ("saved_Cmd_ScaleMemory", "BOOL {newname};"),
        "?scrutinize_generated_il@@3_NA": ("scrutinize_generated_il", "bool {newname};"),
        "?server_filename@@3PAGA": ("server_filename", "wchar_t {newname}[0x400];", partial(make_array_helper, 0x400)),
        "?wszVerCLR@@3PAGA": ("wszVerCLR", "wchar_t {newname}[0x400];", partial(make_array_helper, 0x400)),
        # "Buffer": ("Buffer", "wchar_t {newname}[260];", partial(make_array_helper, 260)), ... name is too generic
    },
    "link.exe": {
        "?CheckErrNo@@YAXXZ": ("CheckErrNo", "void {newname}();"),
        "?CheckHResult@@YA_NJ@Z": ("CheckHResult", "bool {newname}(HRESULT hr);"),
        "?ControlCHandler@@YAHK@Z": ("ControlCHandler", "BOOL {newname}(DWORD CtrlType);"),
        "?CvtCilMain@@YAHHQEAPEAG@Z": ("CvtCilMain", "int {newname}(int argc, wchar_t** argv);"),
        "?CvtCilUsage@@YAXXZ": ("CvtCilUsage", None),
        "?DisableWarning@@YAXI@Z": ("DisableWarning", "void {newname}(unsigned int msgid)"),
        "?DisplayFatal@@YAXPEBG_KW4MSGTYPE@@_NIPEAD@Z": (
            "DisplayFatal",
            "void __noreturn {newname}(wchar_t const *format, __int64 unknown2, unsigned int unknown3, bool unknown4, unsigned int msgid, va_list argptr);",
        ),
        "?DisplayMessage@@YAXPEBG_KW4MSGTYPE@@IPEAD@Z": (
            "DisplayMessage",
            "void {newname}(const wchar_t *format, __int64 unknown2, unsigned int unknown3, unsigned int msgid, va_list argptr);",
        ),
        "?DisplayWarning@@YAXPEBG_KIPEAD@Z": ("DisplayWarning", "void {newname}(const wchar_t *format, __int64 unknown2, unsigned int msgid, va_list argptr);"),
        "?DumperMain@@YAHHQEAPEAG@Z": ("DumperMain", "int {newname}(int argc, wchar_t** argv);"),
        "?DumperUsage@@YAXXZ": ("DumperUsage", None),
        "?EditorMain@@YAHHQEAPEAG@Z": ("EditorMain", "int {newname}(int argc, wchar_t** argv);"),
        "?EmitHelp@@YAXII@Z": ("EmitHelp", "void {newname}(unsigned int toolmsg, unsigned int helpmsg);"),
        "?EndEnmUndefExtNonWeak@@YAXPEAVENM_UNDEF_EXT@@@Z": (
            "EndEnmUndefExtNonWeak",
            "void {newname}(LPCWSTR expression, LPCWSTR function, LPCWSTR file,uint line, uintptr_t);",
        ),
        "?FIgnoreWarning@@YA_NI@Z": ("FIgnoreWarning", "bool FIgnoreWarning(unsigned int msgid);"),
        "?FWarningAsError@@YA_NI@Z": ("FWarningAsError", "bool FWarningAsError(unsigned int msgid);"),  # cs:?fWarningIsError@@3_NA
        "?Fatal@@YAXPEBGIZZ": (
            "Fatal",
            "void __noreturn {newname}(wchar_t const *format, unsigned int msgid, ...);",
        ),  # -> process to comment which message ID is being set (and make the number operand decimal) [EDX]
        "?Fatal@CON@@QEBAXIZZ": (None, "void __noreturn CON::Fatal(CON *__hidden this, unsigned int msgid, ...);"),
        "?FileHardClose@@YAXPEBG_N@Z": ("FileHardClose", "void {newname}(LPCWSTR lpFileName)"),
        "?FileMove@@YAXPEBG0@Z": ("FileMove", "void {newname}(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);"),
        "?FileRemove@@YA_NPEBG@Z": ("FileRemove", "bool {newname}(LPCWSTR FileName);"),
        "?HelperMain@@YAHHQEAPEAG@Z": ("HelperMain", "int {newname}(int argc, wchar_t** argv);"),
        "?HybridPushThunkObjMain@@YAHHQEAPEAG@Z": ("HybridPushThunkObjMain", "int {newname}(int argc, wchar_t** argv);"),
        "?InfoClose@@YAHXZ": ("InfoClose", "int {newname}(void);"),
        "?InfoPrintf@@YAHPEBGZZ": ("InfoPrintf", "int {newname}(wchar_t const *format, ...);"),
        "?InfoVprintf@@YAHPEBGPEAD@Z": (
            "InfoVprintf",
            "int {newname}(wchar_t const *format, va_list argptr);",
        ),  # use to find szOutputRedirectionString and InfoStream globals
        "?LibrarianMain@@YAHHQEAPEAG@Z": ("LibrarianMain", "int {newname}(int argc, wchar_t** argv);"),
        "?LibrarianUsage@@YAXXZ": ("LibrarianUsage", None),
        "?LinkerMain@@YAHHQEAPEAG@Z": ("LinkerMain", "int {newname}(int argc, wchar_t** argv);"),
        "?LinkerUsage@@YAXXZ": ("LinkerUsage", None),
        "?Message@@YAXIZZ": ("Message", "void {newname}(unsigned int, ...);"),
        "?OutputInit@@YAXXZ": ("OutputInit", "void {newname}();"),  # use to find InfoStream and StdoutStream globals
        "?ParseSymbol@@YAXPEBG0_N@Z": ("ParseSymbol", "void {newname}(LPWSTR Source, LPCWSTR, bool);"),
        "?PrintLogo@@YAXXZ": ("PrintLogo", "void PrintLogo(void);"),
        "?ProcessArgument@@YAXPEAG_N11@Z": ("ProcessArgument", "void {newname}(LPWSTR Argument, bool, bool, bool);"),
        "?ProcessCommandFile@@YAXPEBG@Z": ("ProcessCommandFile", "void {newname}(LPCWSTR name);"),
        "?ProcessEditorSwitches@@YAXHPEBGHK_N1@Z": ("ProcessEditorSwitches", "void {newname}(int, LPCWSTR, int, unsigned int, bool, bool);"),
        "?ProcessWildCards@@YAXPEBG@Z": ("ProcessWildCards", "void {newname}(LPCWSTR FileArgument);"),
        "?SHA1Update@SHA1Hash@@AEAAXPEAUSHA1_CTX@@PEBEK@Z": (
            "SHA1Hash__SHA1Update",
            "void {newname}(SHA1Hash *__hidden this, struct SHA1_CTX *, uchar const*buf, ulong buflen);",
        ),
        "?StdOutVprintf@@YAHPEBGPEAD@Z": ("StdOutVprintf", "int {newname}(wchar_t const *format, va_list argptr);"),  # use to find fIsOutputRedirected globals
        "?SzDupWsz@@YAPEADPEBG@Z": ("SzDupWsz", "char* {newname}(LPCWSTR lpWideCharStr);"),
        "?SzTrimFile@@YAPEADPEBD@Z": ("SzTrimFile", "char* {newname}(char const* string1);"),
        "?Warning@@YAXPEBGIZZ": (None, None),  # [EDX]
        "?WarningLine@@YAXPEBG_KIZZ": ("WarningLine", "void {newname}(wchar_t const *format, __int64 unknown2, unsigned int msgid, ...);"),
        "?_find@@YAPEAGPEBG@Z": ("_find", "LPWSTR _find(LPCWSTR lpFileName);"),
        "?link_fclose@@YAHPEAU_iobuf@@@Z": ("link_fclose", "int {newname}(FILE* stream);"),
        "?link_fread@@YA_KPEAX_K1PEAU_iobuf@@@Z": ("link_fread", "size_t {newname}(void *buffer, size_t size, size_t count, FILE *stream);"),
        "?link_fseek@@YAHPEAU_iobuf@@JH@Z": ("link_fseek", "int {newname}(FILE* stream, off_t offset, int origin);"),
        "?link_ftell@@YAJPEAU_iobuf@@@Z": ("link_ftell", "off_t {newname}(FILE* stream);"),
        "?link_fwprintf@@YAHPEAU_iobuf@@PEBGZZ": ("link_fwprintf", "int {newname}(FILE* stream, wchar_t const *format, ...);"),
        "?link_vfwprintf@@YAHPEAU_iobuf@@PEBGPEAD@Z": ("link_vfwprintf", "int {newname}(FILE* stream, wchar_t const *format, va_list argptr);"),
        "?link_wfsopen@@YAPEAU_iobuf@@PEBG0H@Z": ("link_wfsopen", "FILE* {newname}(LPCWSTR filename, LPCWSTR mode, int shflag);"),
        "?wmainInner@@YAHHQEAPEAG@Z": ("wmainInner", "int {newname}(int argc, wchar_t** argv);"),
        "CheckHResultFailure": ("CheckHResultFailure", "void {newname}(HRESULT hr);"),
        "EditorFatal": ("EditorFatal", "void __noreturn EditorFatal(wchar_t *format, unsigned int msgid, ...);"),
        "ExpandOutputString": ("ExpandOutputString", "int {newname}(wchar_t const *format, va_list argptr);"),
        "FIsConsole": ("FIsConsole", "bool {newname}(FILE *stream);"),
        "GetFilePos": ("GetFilePos", "DWORD {newname}(HANDLE hFile);"),
        "main": ("wmain", "int {newname}(int argc, wchar_t** argv);"),
        # Imports
        "__imp_scalable_aligned_free": ("__imp_scalable_aligned_free", "void scalable_aligned_free(void* memblock);"),
        "__imp_scalable_aligned_malloc": ("__imp_scalable_aligned_malloc", "void* scalable_aligned_malloc(size_t size, size_t alignment);"),
        "__imp_scalable_aligned_realloc": ("__imp_scalable_aligned_realloc", "void* scalable_aligned_realloc(void* memblock, size_t size, size_t alignment);"),
        "__imp_scalable_free": ("__imp_scalable_free", "void scalable_free(void* memblock);"),
        "__imp_scalable_malloc": ("__imp_scalable_malloc", "void* scalable_malloc(size_t size);"),
        "__imp_scalable_realloc": ("__imp_scalable_realloc", "void* scalable_realloc(void* memblock, size_t size);"),
        # Data
        "?Dbflags@@3PADA": ("Dbflags", "bool Dbflags[73];", partial(make_array_helper, 73)),
        "?Tool@@3W4TOOL_TYPE@@A": ("Tool", "TOOL_TYPE {newname};"),
        "?ToolName@@3PEBGEB": ("ToolName", "LPWSTR ToolName;"),
        "?ToolType@@3PAUcalltype@@A": ("ToolType", "calltype {newname}[8];", fixup_tooltype),
        "?fCtrlCSignal@@3KA": ("fCtrlCSignal", "uint {newname};"),
        "?fDidInitRgci@@3_NA": ("fDidInitRgci", "bool {newname};"),
        "?fDidMachineDependentInit@@3_NA": ("fDidMachineDependentInit", "bool {newname};"),
        "?fMultipleDefinitions@@3_NA": ("fMultipleDefinitions", "bool {newname};"),
        "?fNoBaseRelocs@@3_NA": ("fNoBaseRelocs", "bool {newname};"),
        "?fNoLogo@@3_NA": ("fNoLogo", "bool {newname};"),
        "?fOpenedOutFilename@@3_NA": ("fOpenedOutFilename", "bool {newname};"),
        "?fUnInitWarbird@@3_NA": ("fUnInitWarbird", "bool {newname};"),
        "?fUnInitWarbird@@3_NA": ("fUnInitWarbird", "bool {newname};"),
        "?fWarningIsError@@3_NA": ("fWarningIsError", "bool {newname};"),
        "?fWbrdReportErrors@@3_NA": ("fWbrdReportErrors", "bool {newname};"),
        "?fWbrdTestEncrypt@@3_NA": ("fWbrdTestEncrypt", "bool {newname};"),
        "?g_cbILKMax@@3_KA": ("g_cbILKMax", "uint64_t g_cbILKMax;"),
        "?g_dwMainThreadId@@3KA": ("g_dwMainThreadId", "DWORD g_dwMainThreadId;"),
        "?g_fArm64XCrossDebug@@3_NA": ("g_fArm64XCrossDebug", "bool {newname};"),
        "?g_fArm64XCrossResolve@@3_NA": ("g_fArm64XCrossResolve", "bool {newname};"),
        "?g_fArm64XHack@@3_NA": ("g_fArm64XHack", "bool {newname};"),
        "?g_fClearLinkRepro@@3_NA": ("g_fClearLinkRepro", "bool {newname};"),
        "?g_fDidPass1DefFile@@3_NA": ("g_fDidPass1DefFile", "bool {newname};"),
        "?g_fFastFail@@3_NA": ("g_fFastFail", "bool {newname};"),
        "?g_fForceNoLinkRepro@@3_NA": ("g_fForceNoLinkRepro", "bool {newname};"),
        "?g_fForceNoOnfailRepro@@3_NA": ("g_fForceNoOnfailRepro", "bool {newname};"),
        "?g_fForcePGORepro@@3_NA": ("g_fForcePGORepro", "bool {newname};"),
        "?g_fIncrClean@@3_NA": ("g_fIncrClean", "bool {newname};"),
        "?g_fInferAsanLibsDone@@3_NA": ("g_fInferAsanLibsDone", "bool {newname};"),
        "?g_fLtcgForcedOff@@3_NA": ("g_fLtcgForcedOff", "bool {newname};"),
        "?g_fObjCoffInitialized@@3_NA": ("g_fObjCoffInitialized", "bool {newname};"),
        "?g_fPGI@@3_NA": ("g_fPGI", "bool {newname};"),
        "?g_fPGO@@3_NA": ("g_fPGO", "bool {newname};"),
        "?g_fPGU@@3_NA": ("g_fPGU", "bool {newname};"),
        "?g_fPrescanSwitches@@3_NA": ("g_fPrescanSwitches", "bool {newname};"),
        "?g_fResolvePlaceholderTlsIndexImport@@3_NA": ("g_fResolvePlaceholderTlsIndexImport", "bool {newname};"),
        "?g_fRunBelow4GB@@3_NA": ("g_fRunBelow4GB", "bool {newname};"),
        "?g_fSEHEmpty@@3_NA": ("g_fSEHEmpty", "bool {newname};"),
        "?g_fSawCIL@@3_NA": ("g_fSawCIL", "bool {newname};"),
        "?g_fSawWinRTMeta@@3_NA": ("g_fSawWinRTMeta", "bool {newname};"),
        "?g_fWarnZwObjInStaticLib@@3_NA": ("g_fWarnZwObjInStaticLib", "bool {newname};"),
        "?g_fWowA64LinkerGeneratedLib@@3_NA": ("g_fWowA64LinkerGeneratedLib", "bool {newname};"),
        "?g_szLTCGOutFilename@@3PEBGEB": ("g_szLTCGOutFilename", "LPCWSTR {newname};"),
        "?szPdbFilename@@3PEAGEA": ("szPdbFilename", "LPCWCH {newname};"),
        "?szPhase@@3PEBGEB": ("szPhase", "LPCWSTR {newname};", fixup_szphase),  # TODO: resolve all assignments to comments
        # ?rgpfi@BufIOPrivate@@3PEAPEAUFI@@EA -> table of file "descriptors", the index is used as "file number"
        # "Library" functions
        "?memcpy_avx@@YAPEBXPEBX0_K@Z": ("memcpy_avx", "void const* {newname}(void * dst, void const* src, size_t count);", None, True),
        "?strdup_TCE@@YAPEADPEBD@Z": ("strdup_TCE", "char* {newname}(char const* strSource);", None, True),
        "?strdup_TCE@@YAXPEBDPEAPEADPEA_K@Z": (None, "void strdup_TCE(char const* Src, char ** Duplicated, size_t * allocated);", None, True),
        "?wcschr@@YAPEAGPEAGG@Z": ("wcschr", "wchar_t * {newname}(const wchar_t *str, wchar_t ch);", None, True),
        "strcmp_0": ("strcmp_0", "int {newname}(char const *str1, char const *str2);", None, True),
        "strncmp_avx": ("strncmp_avx", "int {newname}(char const* str1, char const* str2, size_t count);", None, True),
        "swprintf_s": (None, "int {newname}(wchar_t *const Buffer, const size_t BufferCount, const wchar_t *const Format, ...);", None, True),
        "swscanf_s": (None, "int {newname}(wchar_t const*const buffer, wchar_t const*const format, ...);", None, True),
        "wcscmp_0": (None, "int __cdecl {newname}(const wchar_t *str1, const wchar_t *str2);", None, True),
        "wcsrchr_0": (None, "wchar_t * {newname}(const wchar_t *str, wchar_t ch);", None, True),
    },
}


def retype_single(oldname: str, newname: Optional[str], rule: tuple, tinfo_flags=idc.TINFO_DEFINITE) -> Tuple[bool, Optional[callable], Optional[str]]:
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
    assert rfname, "Expected that the name of the file used to create the IDB has been globally set"
    print(f"INFO: applying renaming and re-typing rules for '{rfname}'")
    if rfname not in renames:
        print(f"WARNING: Could not find '{rfname}' as top-level key in the renaming rules")
        return

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
        lambda x: x.startswith("__scrt_"),
        lambda x: x
        in {
            "??$swprintf_s@$0CAA@@@YAHAEAY0CAA@GPEBGZZ",
            "_vswprintf_s_l",
            "memset_zero_avx",
            "memcpy_s",
            "initialize_legacy_wide_specifiers",
            "fwprintf",
            "_cprintf",
            "_vcprintf_l",
            "_vfprintf_l",
            "_vfwprintf_l",
            "_vsnprintf_s_l",
            "_vsnwprintf_s_l",
            "_vswprintf_s_l",
            "_snwprintf_s",
            "_snprintf_s",
            "__delayLoadHelper2",
        },
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


def find_string_refs():
    stringrefs = {}
    stringctrs = []
    for s in idautils.Strings():
        refs = set()
        for xref in idautils.XrefsTo(s.ea):
            refs.add(xref.frm)
        stringctrs.append((len(refs), xref.to,))  # fmt: skip
        if xref.to in stringrefs:
            stringrefs[xref.to] = refs | stringrefs[xref.to]
        else:
            stringrefs[xref.to] = refs
    stringctrs = sorted(stringctrs, key=lambda x: x[0], reverse=True)
    for num, ea in stringctrs:
        if num > 3:
            print(f"{num}: {ea:#x}")


def apply_per_module_typedefs():
    assert rfname, "Expected that the name of the file used to create the IDB has been globally set"
    if rfname in per_module_typedefs:
        errs = ida_typeinf.parse_decls(None, per_module_typedefs[rfname], None, ida_typeinf.HTI_DCL)
        if errs in {0}:
            print(f"INFO: no errors applying C types for '{rfname}'")
        else:
            print(f"WARNING: {errs} errors applying C types for '{rfname}'")


def find_single_func_containing(needle: str) -> Optional[int]:
    func = [func for func in idautils.Names() if needle in func[1]]
    if len(func) == 1:  # assert len(func) == 1, "Expecting to find the name and a single instance of a name containing '{needle}' only"
        fct = idaapi.get_func(func[0][0])
        if fct:
            return func[0][0]
        else:
            print(f"WARNING: item at {func[0][0]:#x} was not a function")
    else:
        print(f"WARNING: found more than a single name with '{needle}' in it")
    return None


def find_rdata_xrefs_to(ea: int, try_harder: bool = False) -> list[int]:
    """\
        Finds xrefs to a given item (head) in the .rdata segment and returns a tuple
        with a list and a bool. The bool indicates whether brute force was tried or not!
    """
    func = idaapi.get_func(ea)
    retval = []
    if func:
        rdata = idaapi.get_segm_by_name(".rdata")
        # print(f"DEBUG: .rdata spans: {rdata.start_ea:#x} ... {rdata.end_ea:#x}")
        for head in idautils.Heads(rdata.start_ea, rdata.end_ea):
            flags = ida_bytes.get_flags(head)
            if ida_bytes.is_data(flags):
                for xref in idautils.XrefsTo(head, 0):
                    if xref.frm >= func.start_ea and xref.frm < func.end_ea:
                        retval.append(head)
        if not retval or try_harder:  # still empty? Try brute force ...
            print("WARNING: Came up empty-handed, trying brute force now.")
            byteaddr = rdata.start_ea
            while byteaddr < rdata.end_ea:
                flags = ida_bytes.get_flags(byteaddr)
                if ida_bytes.is_data(flags) or ida_bytes.is_unknown(flags):
                    for xref in idautils.XrefsTo(byteaddr, 0):
                        if xref.frm >= func.start_ea and xref.frm < func.end_ea:
                            retval.append(byteaddr)
                            try_harder = True
                byteaddr += ida_bytes.get_item_size(byteaddr)
    else:
        print(f"WARNING: {ea:#x} does not appear to be a function")
    if retval:
        retval = list(set(retval))  # make sure to filter duplicates
    return retval, try_harder


def prettify_cmdswitches(ea: int, typename: str, typesize: int, terminators: dict, PTRSIZE: int = 8) -> Optional[tuple]:
    assert PTRSIZE == 8 and glblinfo.is_64bit(), "This code was designed with 64-bit in mind. 32-bit was never tested."
    known_types = {
        1: "true",
        5: "false",
        8: "c2:unknown",
        10: "callback",
        0x22: "string",
        0x23: "c2:unknown",
        0x24: "decimal",
        0x26: "stringlist_append",
        0x28: "hex",
        0x29: "callback",
        0x2A: "c2:unknown",
        0x2B: "c2:unknown",
        0x2C: "c2:unknown",
        0x2D: "c2:unknown",
    }
    newname = "cmdswitches"
    if not idc.set_name(ea, newname):
        print(f"WARNING: failed to set new name '{newname}' for {ea:#x} ... proceeding anyway")
    rdata = idaapi.get_segm_by_name(".rdata")
    print(f"INFO: Processing likely {ea:#x} (changes will only be done if confirmed)")
    addr = ea
    terminator = terminators[typename]
    arritems = None
    assert len(terminator) == typesize, f"These must be identical, but aren't: {len(terminator)=} != {typesize=}"
    switches = []
    # Try to parse EA as typename elements with typesize each
    while addr < rdata.end_ea:
        record = ida_bytes.get_bytes(addr, typesize)
        strlit_offs = ida_bytes.get_qword(addr)
        switch = get_strlit(strlit_offs)
        if switch:
            # Unpack from record above, which we have already read anyway ...
            not_final = None
            switch_type = None

            if typename in {"c1switch_t"}:
                not_final = ida_bytes.get_byte(addr + 2 * PTRSIZE)
                if not_final not in {0, 1}:
                    print(f"WARNING: record at {addr:#x} contains a value other than 0 or 1 for the 'type' at offset 0x10 at {addr=:#x}")
                switch_type = ida_bytes.get_byte(addr + 2 * PTRSIZE + 1)
                assert switch_type in known_types, f"Encountered unknown switch type {switch_type}/{switch_type:#x} (offset 0x11) at {addr=:#x}"
            elif typename in {"c2switch_t"}:
                switch_type = ida_bytes.get_byte(addr + 3 * PTRSIZE)
                not_final = (
                    ida_bytes.get_dword(addr + 3 * PTRSIZE + 4),
                    ida_bytes.get_qword(addr + 2 * PTRSIZE),
                )
                assert switch_type in known_types, f"Encountered unknown switch type {switch_type}/{switch_type:#x} (offset 0x11) at {addr=:#x}"
            else:
                assert False, f"Not implemented for {typename}"
            switches.append((switch, switch_type, known_types[switch_type], not_final,))  # fmt: skip
        if record == terminator:
            overall = addr + typesize - ea
            arritems = overall // typesize
            assert overall % typesize == 0, f"Unexpectedly {overall} = {addr+typesize:#x} - {ea:#x} was not divisible by {typesize=} without remainder."
            print(f"INFO: found last item at: {addr=:#x} -> {overall=} -> {arritems=}")
            break
        elif switch is None:
            print(f"WARNING: unable read string literal at {strlit_offs:#x} referenced from {addr:#x}")
        addr += typesize
    # This happens if we run into the end of .rdata without hitting a known terminator
    if arritems is None:
        print(f"WARNING: unable determine number of sizeof({typename})=={typesize} records at {ea:#x}")
        return None
    if len(switches) != (arritems - 1):
        print(f"WARNING: expected number of collected switches ({len(switches)}) to match number of array items ({arritems}) minus one. Not the case.")
    # Make unknown bytes across the whole range
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_DELNAMES, addr - ea):
        print(f"WARNING: failed to undefine range between {ea:#x} and {addr:#x}")
        return None
    rule = ((ea, newname,), f"{typename} {newname};",)  # fmt: skip
    # Set struct type (single item initially); this also imports the local type into structs
    done, _, msg = retype_single(newname, None, rule)  # fmt: skip
    print(msg)
    if not done:
        print("ERROR: Cannot proceed.")
        return None
    done, msg = make_array_helper(arritems, ea)
    print(msg)
    if not done:
        print("ERROR: Cannot proceed.")
        return None
    rule = ((ea, newname,), f"{typename} {newname}[{arritems}];",)  # fmt: skip
    # Set C array type this time around ...
    done, _, msg = retype_single(newname, None, rule)  # fmt: skip
    print(msg)
    if not done:
        return None
    print(f"INFO: finished prettifying {newname}.")
    # TODO: mark the items referencing any of the dummy variables
    with open(Path(__file__).absolute().parent / f"{rfname}.yml", "w") as yamlout:
        yaml.safe_dump(switches, stream=yamlout, explicit_start=True, default_flow_style=None)
    return (ea, addr, arritems,)  # fmt: skip


def decode_crack_cmd(PTRSIZE: int = 8):  # remember: assumes 64-bit!
    assert rfname, "Expected that the name of the file used to create the IDB has been globally set"
    assert PTRSIZE == 8 and glblinfo.is_64bit(), "This code was designed with 64-bit in mind. 32-bit was never tested."
    if rfname not in {"c1.dll", "c1xx.dll", "c2.dll"}:
        print(f"WARNING: {rfname} not eligible for crack_cmd decoding")
        return
    needle = "crack_cmd"
    crack_cmd = find_single_func_containing(needle)
    if not crack_cmd:
        print(f"WARNING: found no functions with '{needle}' in the name for {rfname}")
        return
    typename = "c2switch_t" if rfname in {"c2.dll"} else "c1switch_t" if rfname in {"c1.dll", "c1xx.dll"} else None
    if not typename:
        print(f"WARNING: no applicable type name found for cmdswitches {rfname}. Perhaps you forgot to import them?")
        return
    typesize = sizeof(typename)
    terminators = {"c2switch_t": 16 * b"\0" + b"\3" + 15 * b"\0", "c1switch_t": typesize * b"\0"}
    for try_harder in (False, True):
        candidates, tried_harder = find_rdata_xrefs_to(crack_cmd, try_harder)
        if not candidates:
            print(f"WARNING: found no suitable data xrefs to .rdata in function with '{needle}' in the name (at {crack_cmd:#x}) for {rfname}")
            return
        for dataitem in candidates:
            datasize = ida_bytes.get_item_size(dataitem)
            print(f"INFO: Candidate for crack_cmd table: {dataitem:#x}, size={datasize}")
        # Filter the list down
        candidates = [
            x
            for x in candidates
            if (ida_bytes.get_item_size(x) in {PTRSIZE} and ida_typeinf.idc_guess_type(x) in {"char *", "char*", "wchar_t *", "wchar_t*"})
            or (
                ida_bytes.get_item_size(x) in {1}
                and ida_typeinf.idc_guess_type(x) is None
                and ida_bytes.is_unknown(ida_bytes.get_flags(x))
                or (ida_bytes.get_item_size(x) % typesize == 0 and typename in ida_typeinf.idc_guess_type(x))
            )
        ]
        # We simply won't continue if more than a single candidate remains
        if len(candidates) != 1:
            if tried_harder:
                print(f"ERROR: known filter conditions not enough to find tableof command line switches for {rfname}")
                return
            else:
                continue
        result = prettify_cmdswitches(candidates[0], typename, typesize, terminators)
        if result is not None:
            start, end, items = result
            mark_position(result[0], f"Command line switches ({items}) processed in crack_cmd() (size={end - start})")
            break  # looks odd? ... true, but if we get here we don't need to duplicate the work of the ~4 lines above ... no need to "try harder"


def main():
    global rfname
    rfname = idc.get_root_filename()  # get_input_file_path() for IDB _path_
    assert rfname, "Could not retrieve name of the file used to create the IDB"
    clear_output_console()
    apply_per_module_typedefs()
    # find_string_refs()
    decode_crack_cmd()
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
