"""Select advisories affecting the fork baseline and match them to notice #1967.

The unit of analysis is one GHSA advisory. Matching Maven modules are recorded
within the same row.
"""
from pathlib import Path
from datetime import date
import csv, json, math
from analysis_helpers import affected

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT / 'sources'
NOTICE = json.loads((SOURCES/'egov1967_backport_ids.json').read_text(encoding='utf-8'))
BACKPORT_431 = set(NOTICE['backport_cve_ids'])
CUTOFF = date(2026, 10, 29)  # Exclude the 4.3.1 release date; no lower publication-date bound.
FW = 'aop aspects beans context context-indexer context-support core expression instrument jcl jdbc jms messaging orm oxm r2dbc test tx web webflux webmvc websocket'.split()
SEC = 'acl aspects cas config core crypto data ldap messaging oauth2-client oauth2-core oauth2-jose oauth2-resource-server openid remoting rsocket saml2-service-provider taglibs test web'.split()
TRAINS = {**{f'org.springframework:spring-{m}':('Spring Framework','5.3.39') for m in FW}, **{f'org.springframework.security:spring-security-{m}':('Spring Security','5.8.16') for m in SEC},'org.springframework.data:spring-data-mongodb':('Spring Data MongoDB','3.4.18'),'org.springframework.data:spring-data-commons':('Spring Data Commons','2.7.18')}

def train_of(name):
    if name in TRAINS:return TRAINS[name]
    if name.startswith('org.springframework.integration:spring-integration-'):return ('Spring Integration','5.5.20')
    return None

def cisa(cve):
    p=SOURCES/'cve'/f'{cve}.json'
    if not p.exists():raise FileNotFoundError(f'Missing source CVE record: {p}')
    d=json.loads(p.read_text(encoding='utf-8'))
    evaluations=[]
    for adp in d.get('containers',{}).get('adp',[]):
        provider=adp.get('providerMetadata',{})
        if provider.get('shortName')!='CISA-ADP' and provider.get('orgId')!='134c704f-9b21-4f2e-91b3-4a467353bcc0':continue
        for m in adp.get('metrics',[]):
            o=m.get('other',{})
            if o.get('type')!='ssvc':continue
            content=o['content']; options={k:v for x in content.get('options',[]) for k,v in x.items()}
            evaluations.append((content.get('timestamp',''),options))
    if not evaluations:return {},''
    # Use the latest CISA-ADP evaluation available in the pinned record.
    timestamp,options=max(evaluations,key=lambda x:x[0])
    return options,timestamp

def cvss_base(vector):
    # CVSS is descriptive here; it does not determine cohort membership.
    if not vector.startswith(('CVSS:3.0/','CVSS:3.1/')):return ''
    v=dict(p.split(':',1) for p in vector.split('/')[1:]); changed=v['S']=='C'
    weights={'H':.56,'L':.22,'N':0}
    isc=1-math.prod(1-weights[v[x]] for x in 'CIA')
    impact=7.52*(isc-.029)-3.25*(isc-.02)**15 if changed else 6.42*isc
    if impact<=0:return 0.0
    av={'N':.85,'A':.62,'L':.55,'P':.2}[v['AV']]
    ac={'L':.77,'H':.44}[v['AC']]
    pr=({'N':.85,'L':.68,'H':.50} if changed else {'N':.85,'L':.62,'H':.27})[v['PR']]
    ui={'N':.85,'R':.62}[v['UI']]
    total=min(10,(impact+8.22*av*ac*pr*ui)*(1.08 if changed else 1))
    return math.ceil(round(total,5)*10-1e-10)/10

def build():
    rows=[];seen=set()
    for path in sorted((SOURCES/'ghsa').glob('*.json')):
        a=json.loads(path.read_text(encoding='utf-8'))
        if a.get('withdrawn') or not a.get('database_specific',{}).get('github_reviewed'):continue
        pub=date.fromisoformat(a['published'][:10])
        if pub>=CUTOFF:continue
        trains,pkgs=set(),set()
        for af in a.get('affected',[]):
            package=af.get('package',{})
            if package.get('ecosystem')!='Maven':continue
            n=package['name'];t=train_of(n)
            if t and affected(t[1],af.get('ranges',[]),af.get('versions',[])):
                trains.add(t[0]);pkgs.add(n.split(':')[1])
        if not trains:continue
        if a['id'] in seen:raise ValueError('Duplicate GHSA ID: '+a['id'])
        seen.add(a['id'])
        cves=[c for c in a.get('aliases',[]) if c.startswith('CVE-')]
        if len(cves)!=1:raise ValueError(f'Explicit alias handling required: {a["id"]}: {cves}')
        options,_=cisa(cves[0])
        vector=next((s['score'] for s in a.get('severity',[]) if s['type']=='CVSS_V3'),'')
        rows.append(dict(ghsa=a['id'],cve=cves[0],published=str(pub),lead=(CUTOFF-pub).days,train=';'.join(sorted(trains)),pkgs=';'.join(sorted(pkgs)),severity=a.get('database_specific',{}).get('severity',''),cvss=cvss_base(vector),exploitation=options.get('Exploitation',''),backported=int(any(c in BACKPORT_431 for c in cves)),summary=a.get('summary','')))
    return sorted(rows,key=lambda r:(r['published'],r['ghsa']))

def write_rows(path,rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    if NOTICE['notice_number'] != 1967 or len(BACKPORT_431) != 15:
        raise ValueError('Expected the 15 distinct CVEs transcribed from notice #1967')
    rows=build();write_rows(ROOT/'backport_population.csv',rows)
    report={'n':len(rows),'backport_list_matches':sum(x['backported'] for x in rows),'publication_min':min(x['published'] for x in rows),'publication_max':max(x['published'] for x in rows),'distinct_ghsa':len({x['ghsa'] for x in rows}),'distinct_cve':len({x['cve'] for x in rows}),'official_backport_cves_outside_population':sorted(BACKPORT_431-{x['cve'] for x in rows})}
    (ROOT/'backport_summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
