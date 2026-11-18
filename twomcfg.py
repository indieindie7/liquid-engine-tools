"""twomcfg.py <execlasses.tsv> <file.bin> <TopClass|auto> [out.json] [--skip HEXFLAGS] [--trace]
Reader for 11 bit Liquid engine binary property files (config objects), driven by the property tables
that exeprops.py pulls from the exe. Prints 'OK <class> end=<pos> size=<n>' when the parse lands on the file end.
'auto' tries every class in the table as the top class and keeps the ones that land on the file end."""
import sys, struct, json
MARK = 0xdeadd00d
MARKB = struct.pack('<I', MARK)
PRIM = {'uint': 'I', 'int': 'i', 'float': 'f', 'bool': 'B', 'u8': 'B', 'i8': 'b', 'u16': 'H', 'i16': 'h', 'i64': 'q', 'u64': 'Q',
        'Vector': '4f', 'Vector3': '3f', 'Vector2': '2f', 'Quaternion': '4f', 'HDRColor': '4f', 'Matrix': '16f', 'BoundingBox4': '8f', 'SimpleGUID': '16B'}
BASE_LAST = set()  # classes whose base properties are stored after their own (found per data set by twomscan)
MANGLED = {'M': 'float', 'H': 'int', 'I': 'uint', 'G': 'u16', 'E': 'u8', '_N': 'bool', 'F': 'i16', 'D': 'i8'}
ERRS = (ValueError, struct.error, IndexError, RecursionError, UnicodeDecodeError)
POLY1, POLYN = 'RTTIEmbeddedPolyObjectPointerProperty', 'RTTIDynarrayOfPolyObjectPointersProperty'

def load_tables(tsv):
    cls, bases = {}, {}
    for ln in (l for t in tsv.split(',') for l in open(t, encoding='utf-8')):
        f = ln.rstrip('\n').split('\t')
        if f[0] == 'C': bases[f[2]] = f[3]; cls.setdefault(f[2], [])
        elif f[0] == 'P': cls.setdefault(f[1], []).append((f[2], f[3], int(f[4] or '0', 16)))
    return cls, bases

class Reader:
    def __init__(s, d, cls, bases, skip=0x4000, trace=False):
        s.d, s.p, s.cls, s.bases, s.skip, s.trace, s.depth, s.base_last = d, 0, cls, bases, skip, trace, 0, BASE_LAST
    def u(s, fmt):
        v = struct.unpack_from('<' + fmt, s.d, s.p); s.p += struct.calcsize('<' + fmt)
        return v[0] if len(v) == 1 else list(v)
    def count(s):
        n = s.u('I')
        if n > len(s.d) - s.p: raise ValueError('count %d too big at %x' % (n, s.p - 4))
        return n
    def name(s):
        t = s.d[s.p]; s.p += 1
        if t == 0: return ''
        if t != 1: raise ValueError('string tag %d at %x' % (t, s.p - 1))
        e = s.d.index(b'\0', s.p); v = s.d[s.p:e].decode('cp1250'); s.p = e + 1
        return v
    def prim(s, t):
        if t in ('NameString', 'cstr'): return s.name()
        t = MANGLED.get(t, t)
        if t not in PRIM: raise ValueError('unknown primitive %s at %x' % (t, s.p))
        v = s.u(PRIM[t])
        if isinstance(v, float): return round(v, 6)
        if isinstance(v, list) and t != 'SimpleGUID': return [round(x, 6) for x in v]
        return v
    def props_of(s, c, seen=()):
        """Own properties in registration order; a BASE row is replaced by the base's list at that place.
        Each class level is announced by a ('', 'LEVEL', 0) entry: an optional marker + version sits there."""
        out, had = [('', 'LEVEL', 0)], False
        for name, t, fl in s.cls.get(c, []):
            if t == 'BASE':
                if name not in seen and name != c: out += s.props_of(name, seen + (c,)); had = True
                out.append(('', 'LEVEL', 0))
            else: out.append((name, t, fl))
        b = s.bases.get(c)
        if not had and b and b in s.cls and b != c and b not in seen: out = s.props_of(b, seen + (c,)) + out
        if c in s.base_last and had:
            n = len(s.props_of(s.bases[c], seen + (c,))) + 1
            out = [out[0]] + out[n + 1:] + out[1:n + 1]
        return out
    def marked(s): return s.d[s.p:s.p + 4] == MARKB
    def poly_start(s, strict=False):
        """True when a polymorphic element starts at the cursor: the name of a known class, or (not strict) an empty one."""
        if s.p >= len(s.d) or s.d[s.p] == 0: return not strict
        e = s.d.find(bytes(1), s.p + 1, s.p + 120)
        return s.d[s.p] == 1 and e > 0 and s.d[s.p + 1:e].decode('latin1') in s.cls
    def poly(s, more=False):
        """Class name then object. more = another element follows: when no class name starts right after
        this one, the other base block order is tried and kept if it does end on a class name."""
        c = s.name()
        if not c: return None
        if c not in s.cls: raise ValueError('unknown poly class %s at %x' % (c, s.p))
        p0 = s.p
        o = s.obj(c)
        if more and not s.poly_start(True) and any(t == 'BASE' for _, t, _ in s.cls[c]):
            p1, soft = s.p, s.poly_start()
            s.p = p0; s.base_last.symmetric_difference_update({c})
            try: o2 = s.obj_once(c)
            except ERRS: o2 = None
            if o2 is not None and s.poly_start(True): o = o2
            else:
                s.base_last.symmetric_difference_update({c}); s.p = p1
                if not soft: raise ValueError('poly element %s does not end on the next element at %x' % (c, s.p))
        elif more and not s.poly_start(): raise ValueError('poly element %s does not end on the next element at %x' % (c, s.p))
        o['_class'] = c
        return o
    def value(s, c, name, t):
        k, _, a = t.partition('<'); a = a.rstrip('>')
        if k == 'DA': return s.prim(a)
        if k == 'Dyn': return [s.prim(a) for _ in range(s.count())]
        if k in ('DynObj', 'DynObjPtr'): return [s.obj(a, s.marked()) for _ in range(s.count())]
        if k == 'Obj': return s.obj(a, s.marked())
        if k == POLY1: return s.poly()
        if k == POLYN:
            n = s.count()
            return [s.poly(i < n - 1) for i in range(n)]
        raise ValueError('unhandled type %r for %s.%s at %x' % (t, c, name, s.p))
    def base_chain(s, c):
        """c and its bases, as far as each one registers a base block."""
        out = []
        while c and c not in out and any(t == 'BASE' for _, t, _ in s.cls.get(c, [])):
            out.append(c); c = s.bases.get(c)
        return out
    def obj(s, c, marked=False):
        """Object of class c. The base block sits before or after the own properties depending on the class;
        when the stored guess fails inside the object the other orders of c and its bases are tried and the one that parses is remembered (BASE_LAST)."""
        p0, d0 = s.p, s.depth
        try: return s.obj_once(c)
        except ERRS:
            chain = s.base_chain(c)
            if not chain: raise
            for m in range(1, 1 << min(len(chain), 5)):
                sub = [x for i, x in enumerate(chain) if m >> i & 1]
                s.p, s.depth = p0, d0
                s.base_last.symmetric_difference_update(sub)
                try: return s.obj_once(c)
                except ERRS: s.base_last.symmetric_difference_update(sub)
            s.p, s.depth = p0, d0
            raise
    def obj_once(s, c):
        o = {}
        s.depth += 1
        if s.depth > 60: raise ValueError('too deep')
        for name, t, fl in s.props_of(c):
            if t == 'LEVEL':
                if s.marked(): s.p += 4; o.setdefault('_v', []).append(s.u('I'))
                continue
            if t.startswith('RTTIPropertyGroup') or t.startswith('RTTIPropertySeparator') or (fl & s.skip): continue
            if s.trace: print('%x %s.%s %s' % (s.p, c, name, t))
            o[name] = s.value(c, name, t)
        s.depth -= 1
        return o

def parse(d, cls, bases, top, skip, trace=False, start=4):
    r = Reader(d, cls, bases, skip, trace); r.p = start
    try:
        res = r.obj(top, r.marked())
    except ERRS as e:
        return None, r.p, str(e)
    return res, r.p, ''

def find_top(d, cls, bases, tops, skip, trace=False):
    """First class whose parse lands on the file end; size prefix (start 4) tried before none (start 0)."""
    last = (None, 0, 'no class')
    for start in (4, 0):
        for c in tops:
            before = set(BASE_LAST)
            got, end, err = parse(d, cls, bases, c, skip, trace, start)
            if got and BASE_LAST != before: got, end, err = parse(d, cls, bases, c, skip, trace, start)  # reread with the learned orders
            if not got: BASE_LAST.clear(); BASE_LAST.update(before)
            if got and end == len(d): return c, got, end, ''
            last = (c, end, err)
    return last[0], None, last[1], last[2] or 'short'

def parse_args(argv):
    args = [a for a in argv if not a.startswith('--')]
    skip = 0x4000
    if '--skip' in argv:
        v = argv[argv.index('--skip') + 1]; skip = int(v, 16); args.remove(v)
    return args, skip

def main():
    args, skip = parse_args(sys.argv[1:])
    cls, bases = load_tables(args[0])
    d = open(args[1], 'rb').read()
    tops = sorted(c for c in cls if cls[c]) if args[2] == 'auto' else [args[2]]
    c, got, end, err = find_top(d, cls, bases, tops, skip, '--trace' in sys.argv)
    if got is None: print('NOMATCH' if args[2] == 'auto' else 'FAIL', c, 'end=%d size=%d' % (end, len(d)), err); return
    print('OK', c, 'end=%d size=%d' % (end, len(d)))
    if len(args) > 3: json.dump(got, open(args[3], 'w', encoding='utf-8'), indent=1, ensure_ascii=False)

if __name__ == '__main__': main()
