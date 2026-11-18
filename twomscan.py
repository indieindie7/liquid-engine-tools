"""twomscan.py <execlasses.tsv> <dir|file> <out.jsonl> [ClassRegex]
Pulls embedded polymorphic objects out of 11 bit binary files (entity templates) without decoding the
whole file: finds every '\\x01<ClassName>\\x00' whose class is in the property table and parses the
object that follows with twomcfg.Reader. One JSON line per object: file, offset, class, end, obj."""
import sys, os, re, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twomcfg

def scan_file(path, cls, bases, pat):
    d = open(path, 'rb').read()
    for m in re.finditer(rb'\x01([A-Za-z_]\w{3,80})\x00', d):
        c = m.group(1).decode()
        if c not in cls or not cls[c] and not bases.get(c) or not pat.search(c): continue
        got, end, err = twomcfg.parse(d, cls, bases, c, 0x4000, False, m.end())
        yield {'file': os.path.basename(path), 'offset': m.start(), 'class': c, 'end': end, 'err': err, 'obj': got}

def scan_all(files, cls, bases, pat):
    return [rec for p in files for rec in scan_file(p, cls, bases, pat)]

def pick_base_last(files, cls, bases, pat):
    """A first pass lets the reader learn which classes store their base block last."""
    scan_all(files, cls, bases, pat)
    return set(twomcfg.BASE_LAST)

def main():
    tsv, src, out = sys.argv[1:4]
    pat = re.compile(sys.argv[4] if len(sys.argv) > 4 else '.')
    cls, bases = twomcfg.load_tables(tsv)
    files = [os.path.join(src, f) for f in sorted(os.listdir(src))] if os.path.isdir(src) else [src]
    print('base last:', ' '.join(sorted(pick_base_last(files, cls, bases, pat))))
    recs = scan_all(files, cls, bases, pat)
    with open(out, 'w', encoding='utf-8') as fo:
        for rec in recs: fo.write(json.dumps(rec, ensure_ascii=False) + chr(10))
    print('objects', len(recs), 'failed', sum(r['obj'] is None for r in recs))

if __name__ == '__main__': main()
