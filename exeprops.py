"""exeprops.py <exe> <out.tsv>
Property registration tables of an MSVC x64 exe built on RTTI*Property<T> classes (11 bit Liquid engine).
Finds vtables of RTTI classes named *Property*, then disassembles every function that touches one and
recovers, in registration order: property name, property class (type), flags, field offset.
Rows: C<TAB>func_rva<TAB>class<TAB>base   P<TAB>class<TAB>name<TAB>type<TAB>flags<TAB>offset<TAB>group"""
import sys, struct, re, bisect, pefile, capstone
from capstone import x86_const as X
exe, out = sys.argv[1], sys.argv[2]
pe = pefile.PE(exe, fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
secs = {s.Name.rstrip(b'\0').decode(): s for s in pe.sections}
def rng(s): return s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
tx0, tx1 = rng(secs['.text']); rd0, rd1 = rng(secs['.rdata']); da0, da1 = rng(secs['.data'])
td = {m.start() - 16: m.group()[:-1].decode() for m in re.finditer(rb'\.\?A[VU][\x21-\x7e]{1,400}?@@\x00', img)}
col = {}
for o in range(rd0, rd1 - 24, 4):
    sig, _, _, t, _, slf = struct.unpack_from('<6I', img, o)
    if sig == 1 and slf == o and t in td: col[o] = td[t]
vt = {}
for o in range(rd0, rd1 - 8, 8):
    p = struct.unpack_from('<Q', img, o)[0] - base
    if p in col and 'Property' in col[p]: vt[o + 8] = col[p]
def cstr(r):
    if not (rd0 <= r < rd1 or da0 <= r < da1): return None
    e = img.find(b'\0', r, r + 200)
    if e <= r: return None
    s = img[r:e]
    return s.decode() if all(32 <= c < 127 for c in s) else None
ents = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
starts = [a for a, _ in ents]
def func_of(a):
    i = bisect.bisect_right(starts, a) - 1
    return ents[i] if i >= 0 and a < ents[i][1] else None
touch = {}
for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', img[tx0:tx1]):
    a = tx0 + m.start()
    t = a + 7 + struct.unpack_from('<i', img, a + 3)[0]
    if t in vt:
        f = func_of(a)
        if f: touch.setdefault(f, []).append(vt[t])
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
def short(n):
    n = n.replace('.?AV?$', '').replace('.?AV', '')
    n = n.replace('RTTIDirectAccessTypedProperty', 'DA').replace('RTTIDynarrayOfEmbeddedObjectPointersProperty', 'DynObjPtr')
    n = n.replace('RTTIDynarrayOfEmbeddedObjectsProperty', 'DynObj').replace('RTTIDynarrayProperty', 'Dyn').replace('RTTIEmbeddedObjectProperty', 'Obj')
    m = re.match(r'(\w+)@(.*)', n)
    if not m: return n
    k, a = m.groups()
    a = re.sub(r'V\?\$Dynarray\w*@.*', '', a)
    a = re.sub(r'^[UV](\w+)@@.*', r'\1', a)
    a = {'_N@@': 'bool', 'M@@': 'float', 'H@@': 'int', 'I@@': 'uint', 'E@@': 'u8', 'D@@': 'i8', 'G@@': 'u16', 'F@@': 'i16', 'PEAD@@': 'cstr', 'PEAG@@': 'wstr', '_J@@': 'i64', '_K@@': 'u64'}.get(a, a.rstrip('@'))
    return '%s<%s>' % (k, a)
ctor_type = {}
def callee_type(t):
    if t not in ctor_type:
        f = func_of(t)
        v = touch.get(f) if f and f[0] == t else None
        ctor_type[t] = short(v[-1]) if v else ''
    return ctor_type[t]
REG64 = {}
def canon(r):
    return md.reg_name(r)
allrecs = []
for (f0, f1) in sorted(touch):
    regvt, cur, recs, strs = {}, None, [], []
    last = {}; pend = {'flags': 0, 'grp': ''}
    a = f0
    while a < f1:
        got = False
        for i in md.disasm(img[a:f1], a):
            got = True; a = i.address + i.size
            ops = i.operands
            if i.id == X.X86_INS_LEA and ops[1].mem.base == X.X86_REG_RIP:
                t = i.address + i.size + ops[1].mem.disp
                dst = canon(ops[0].reg)
                if t in vt: regvt[dst] = short(vt[t])
                else:
                    regvt.pop(dst, None)
                    s = cstr(t)
                    if s is not None:
                        strs.append(s)
                        if dst == 'rdx':
                            cur = {'name': s, 'type': '', 'flags': pend['flags'], 'off': -1, 'grp': pend['grp'], 'call': 0, 'r8': '', 'ct': 0}
                            recs.append(cur)
                        elif dst == 'r9':
                            pend['grp'] = s
                            if cur is not None and not cur['call']: cur['grp'] = s
                        if dst == 'r8' and cur is not None and not cur['call']: cur['r8'] = s
            elif i.id == X.X86_INS_MOV and len(ops) == 2:
                if ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_IMM and canon(ops[0].reg) == 'r8d':
                    pend['flags'] = ops[1].imm
                    if cur is not None and not cur['call']: cur['flags'] = ops[1].imm
                elif ops[0].type == X.X86_OP_MEM and ops[1].type == X.X86_OP_REG and ops[0].mem.disp == 0 and canon(ops[1].reg) in regvt and cur is not None:
                    cur['type'] = regvt[canon(ops[1].reg)]
                elif ops[0].type == X.X86_OP_MEM and ops[1].type == X.X86_OP_IMM and ops[0].size == 4 and cur is not None and cur['call'] and cur['off'] < 0 and ops[0].mem.base not in (X.X86_REG_RSP, X.X86_REG_RBP, X.X86_REG_RIP):
                    cur['off'] = ops[1].imm
                elif ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_REG:
                    s, d = canon(ops[1].reg), canon(ops[0].reg)
                    if s in regvt: regvt[d] = regvt[s]
                    else: regvt.pop(d, None)
            elif i.id == X.X86_INS_XOR and len(ops) == 2 and ops[0].type == X.X86_OP_REG and canon(ops[0].reg) == 'r8d':
                if cur is not None and not cur['call']: cur['flags'] = 0
            elif i.id == X.X86_INS_CALL:
                if cur is not None and not cur['call']:
                    cur['call'] = 1
                    if ops[0].type == X.X86_OP_IMM:
                        cur['ct'] = ops[0].imm
                        t = callee_type(ops[0].imm)
                        if t: cur['type'] = t
                    # stack args: offset often passed as 5th arg
                for r in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'): regvt.pop(r, None)
                pend = {'flags': 0, 'grp': ''}
        if not got: a += 1
        elif a < f1 and not got: a += 1
        else:
            # disasm stopped early on bad bytes
            if a < f1: a += 1
    if not recs: continue
    allrecs.append(recs)
def regcall(allrecs):
    """The class registration call = the commonest call target taken by the first named record of a function."""
    cnt = {}
    for recs in allrecs: cnt[recs[0]['ct']] = cnt.get(recs[0]['ct'], 0) + 1
    return max(cnt, key=cnt.get)
def class_blocks(allrecs, rc):
    """Split records into (class, r8 base, property records); a class registered twice keeps its first block."""
    blocks, seen = [], set()
    for recs in allrecs:
        cur = None
        for r in recs:
            if r['ct'] == rc:
                cur = None if r['name'] in seen else (r['name'], r['r8'], [])
                if cur: seen.add(cur[0]); blocks.append(cur)
            elif cur: cur[2].append(r)
    return blocks, seen
def baselink(blocks, names):
    """Call target that links a class to its base = the commonest call among untyped records naming a class."""
    cnt = {}
    for _, _, props in blocks:
        for r in props:
            if not r['type'] and r['name'] in names: cnt[r['ct']] = cnt.get(r['ct'], 0) + 1
    return max(cnt, key=cnt.get)
def build_rows(allrecs):
    blocks, names = class_blocks(allrecs, regcall(allrecs))
    bl, rows = baselink(blocks, names), []
    for cls, base, props in blocks:
        own = []
        for r in props:
            if not r['type'] and r['ct'] == bl and r['name'] != cls:
                if r['name'] == 'RTTIPropertiesBase': continue
                base = base or r['name']; r = dict(r, type='BASE')
            own.append(r)
        rows.append(('C', '', cls, base if base != 'RTTIPropertiesBase' else ''))
        rows += [('P', cls, r['name'], r['type'], '%x' % r['flags'], '%x' % r['off'] if r['off'] >= 0 else '', r['grp']) for r in own]
    return rows
rows = build_rows(allrecs)
with open(out, 'w', encoding='utf-8') as fo:
    for r in rows: fo.write('\t'.join(r) + '\n')
print('classes', sum(r[0] == 'C' for r in rows), 'props', sum(r[0] == 'P' for r in rows), 'untyped', sum(r[0] == 'P' and not r[3] for r in rows))
