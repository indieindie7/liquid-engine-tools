"""twomauto.py <tsv[,tsv]> <dir> <outdir>
Runs twomcfg auto mode over every .bin in a directory (shader files skipped); one JSON per parsed file,
one line per file on stdout."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twomcfg

def main():
    tsv, src, out = sys.argv[1:4]
    cls, bases = twomcfg.load_tables(tsv)
    tops = sorted(c for c in cls if cls[c])
    os.makedirs(out, exist_ok=True)
    for f in sorted(os.listdir(src)):
        if not f.endswith('.bin'): continue
        d = open(os.path.join(src, f), 'rb').read()
        if d[:4] == bytes.fromhex('d61b98f3') or len(d) < 8: continue
        c, got, end, err = twomcfg.find_top(d, cls, bases, tops, 0x4000)
        print(f, 'OK ' + c if got else 'NOMATCH', len(d))
        if got: json.dump(got, open(os.path.join(out, f[:-4] + '.json'), 'w', encoding='utf-8'), indent=1, ensure_ascii=False)

if __name__ == '__main__': main()
