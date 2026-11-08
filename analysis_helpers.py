"""Version-range checks for the scoped GHSA records and SSVC utility mapping."""
import re

PRE = {'alpha', 'a', 'beta', 'b', 'milestone', 'm', 'rc', 'cr', 'snapshot', 'pre', 'preview', 'ea'}

NEUTRAL = {'release', 'final', 'ga', ''}

def mkey(v):
    # The scoped records use numeric releases and release qualifiers.
    out = []
    for p in re.split(r'[.\-_]', v.strip()):
        if p.isdigit():
            out.append((1, int(p), ''))
            continue
        m = re.match(r'([a-zA-Z]+)(\d*)$', p)
        q = (m.group(1) if m else p).lower()
        n = int(m.group(2)) if m and m.group(2) else 0
        if q in NEUTRAL:
            continue
        out.append((0, -1, q) if q in PRE else (2, n, q))  # Order prerelease, numeric, and post-release tokens.
    while out and out[-1] == (1, 0, ''):
        out.pop()
    return out

def cmp(a, b):
    ka, kb = mkey(a), mkey(b)
    for x, y in zip(ka, kb):
        if x != y:
            return -1 if x < y else 1
    if len(ka) == len(kb):
        return 0
    longer, sign = (ka, 1) if len(ka) > len(kb) else (kb, -1)
    nxt = longer[min(len(ka), len(kb))]
    return -sign if nxt[0] == 0 else sign

def affected(ver, ranges, versions):
    if ver in versions:
        return True
    # A fixed version is excluded; a last-affected version is included.
    for r in ranges:
        if r.get('type') != 'ECOSYSTEM':
            continue
        state = res = False
        for e in r['events']:
            if 'introduced' in e:
                if e['introduced'] == '0' or cmp(ver, e['introduced']) >= 0:
                    state = True
            elif 'fixed' in e:
                if state and cmp(ver, e['fixed']) < 0:
                    res = True
                state = False
            elif 'last_affected' in e:
                if state and cmp(ver, e['last_affected']) <= 0:
                    res = True
                state = False
        if state:
            res = True
        if res:
            return True
    return False

def utility(auto, vd):
    if auto == "no" and vd == "diffuse":
        return "laborious"
    if auto == "yes" and vd == "concentrated":
        return "super effective"
    return "efficient"
