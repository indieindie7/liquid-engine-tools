"""twomidx.py <game dir> <archive name> [outdir]  -- list / unpack an 11 bit .idx/.dat pair (read-only on the game).
idx: 3 byte magic, u32 count, 4 bytes ?, then 17-byte entries: u32 hash, u32 csize, u32 size, u32 offset, u8 flag (1 = zlib)."""
import sys, struct, zlib, os, collections
g, name = sys.argv[1], sys.argv[2]
out = sys.argv[3] if len(sys.argv) > 3 else None
idx = open(os.path.join(g, name + '.idx'), 'rb').read()
n = struct.unpack_from('<I', idx, 3)[0]
print('magic', idx[:3].hex(), 'count', n, 'hdr', idx[7:11].hex(), 'expect', 11 + 17 * n, 'len', len(idx))
dat = open(os.path.join(g, name + '.dat'), 'rb')
kinds = collections.Counter()
for i in range(n):
    h, cs, sz, off, fl = struct.unpack_from('<IIIIB', idx, 11 + 17 * i)
    dat.seek(off); b = dat.read(cs)
    if fl & 1:
        try: b = zlib.decompressobj(31).decompress(b)
        except Exception as e:
            try: b = zlib.decompress(b, -15)
            except Exception: kinds['ZERR'] += 1; continue
    head = b[:8]
    k = head[:4].hex() if not head[:5].strip().startswith(b'<') else 'xml'
    if all(32 <= c < 127 or c in (9, 10, 13) for c in b[:64]) and k != 'xml': k = 'text'
    kinds[k] += 1
    if out:
        os.makedirs(out, exist_ok=True)
        ext = {'xml': '.xml', 'text': '.txt'}.get(k, '.bin')
        open(os.path.join(out, '%08x%s' % (h, ext)), 'wb').write(b)
    elif i < 5: print('%08x cs=%d sz=%d off=%d fl=%d' % (h, cs, sz, off, fl), b[:48])
print(kinds.most_common(12))
