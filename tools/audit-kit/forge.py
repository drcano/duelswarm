# Forge a chain: insert events, then recompute every hash from genesis (unkeyed sha256 => always possible).
import json,hashlib,sys
G="0"*64
def rehash(es):
    prev=G
    for i,e in enumerate(es):
        e['seq']=i; e['prev']=prev
        e.pop('hash',None)
        body=json.dumps(e,sort_keys=True,separators=(",",":"))
        e['hash']=hashlib.sha256((prev+body).encode()).hexdigest(); prev=e['hash']
    return es
mode,src,dst=sys.argv[1:4]
es=[json.loads(l) for l in open(src)]
if mode=='byte':      # one-byte tamper, no rehash
    lines=open(src).read().splitlines(); i=len(lines)//2
    lines[i]=lines[i].replace('"red"','"rad"',1); open(dst,'w').write("\n".join(lines)+"\n"); sys.exit()
k=max(i for i,e in enumerate(es) if e['action']=='gate.block')
t=dict(es[k]); d=dict(t['data'])
if mode=='oos_allow':      # an out-of-scope EXECUTION recorded honestly as gate.allow to dc-01
    d.pop('reason',None); t['action']='gate.allow'; t['data']=d; es.insert(k+1,t)
elif mode=='oos_fingerprint':  # an out-of-scope effect recorded under a non-EXEC event name
    es.insert(k+1,{'action':'fingerprint','actor':'red','data':{'target':'dc-01','port':22,'server':'OpenSSH','status':200},'ts':t['ts']})
elif mode=='oos_shell_after_block':  # an EXEC-class event against a host blocked earlier
    es.insert(k+1,{'action':'shell','actor':'red','data':{'target':'dc-01','cmd':'id'},'ts':t['ts']})
elif mode=='oos_mutate':   # a lateral state change ONTO dc-01
    es.insert(k+1,{'action':'state.mutate','actor':'red','data':{'state':'lateral','dst':'10.50.0.11','src':'dba01','via_confirm':1},'ts':t['ts']})
open(dst,'w').write("".join(json.dumps(e)+"\n" for e in rehash(es)))
