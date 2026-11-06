# Independent chain walker. Written from the stated formula only; imports nothing from the repo.
import hashlib, json, sys, gzip, glob, collections
G="0"*64
def load(p):
    op = gzip.open if p.endswith('.gz') else open
    with op(p,'rt') as f: return [json.loads(l) for l in f if l.strip()]
def walk(es):
    prev=G
    for i,e in enumerate(es):
        if 'hash' not in e or 'prev' not in e: return ('NOT_A_CHAIN',i)
        if e['prev']!=prev: return ('BAD_PREV',i)
        body=json.dumps({k:v for k,v in e.items() if k!='hash'},sort_keys=True,separators=(",",":"))
        if hashlib.sha256((prev+body).encode()).hexdigest()!=e['hash']: return ('BAD_HASH',i)
        prev=e['hash']
    return ('OK',len(es))
if __name__=='__main__':
    res=collections.Counter()
    for p in sys.argv[1:]:
        try: es=load(p)
        except Exception as ex: print('UNREADABLE',p,ex); continue
        r=walk(es); res[r[0]]+=1
        if r[0]!='OK': print(r,p)
    print(res)
