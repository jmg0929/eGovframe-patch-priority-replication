"""Evaluate the advisory cohort with the CERT/CC supplier decision table.

Hold value density fixed within each run. When a CISA-ADP input is absent,
retain all admissible values for that input.
"""
import argparse,csv,itertools,json
from backport import ROOT,SOURCES,cisa,write_rows
from analysis_helpers import utility

ORDER=['defer','scheduled','out-of-cycle','immediate']
RANK={x:i for i,x in enumerate(ORDER)}
EXP={'none':'none','poc':'public poc','active':'active'}

def table():
    rows=list(csv.DictReader((SOURCES/'supplier_patch_development_priority_1_0_0.csv').open(encoding='utf-8-sig')))
    out={}
    for r in rows:
        v=list(r.values());out[tuple(v[1:5])]=v[5]
    assert len(out)==36
    # Verify that the compact table used in the survey model encodes the same 36 rows.
    from egovframe_priority_reproduce import TABLE,UTILITIES,IMPACTS
    abbreviations={'defer':'D','scheduled':'S','out-of-cycle':'O','immediate':'I'}
    for (e,u,t,p),v in out.items():
        assert abbreviations[v]==TABLE[e][UTILITIES.index(u)*2+IMPACTS.index(t)][p=='significant']
    return out

def calculate(value_density):
    t=table();population=list(csv.DictReader((ROOT/'backport_population.csv').open(encoding='utf-8-sig')))
    rows=[];evidence=[]
    for r in population:
        c,timestamp=cisa(r['cve'])
        e=[EXP[c['Exploitation']]] if 'Exploitation' in c else list(EXP.values())
        a=[c['Automatable']] if 'Automatable' in c else ['no','yes']
        ti=[c['Technical Impact']] if 'Technical Impact' in c else ['partial','total']
        by_psi={p:sorted({t[(ex,utility(au,value_density),im,p)] for ex,au,im in itertools.product(e,a,ti)},key=RANK.get) for p in ['minimal','significant']}
        vals=sorted(set(sum(by_psi.values(),[])),key=RANK.get)
        # Attribute a change to safety alone only when all technical inputs are fixed.
        complete=len(e)==len(a)==len(ti)==1
        rows.append(dict(cve=r['cve'],severity=r['severity'],cvss=r['cvss'],backported=r['backported'],cisa=int(bool(c)),lo=vals[0],hi=vals[-1],n_out=len(vals),psi_decides=int(complete and len(vals)>1),hi_ge_ooc=int(RANK[vals[-1]]>=RANK['out-of-cycle']),summary=r['summary']))
        evidence.append({'cve':r['cve'],'cisa_timestamp':timestamp,'source_file':f"sources/cve/{r['cve']}.json",'technical_options':c,'value_density':value_density,'complete_technical_inputs':complete,'outcomes_by_safety':by_psi})
    return rows,evidence

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--value-density',choices=['concentrated','diffuse'],default='concentrated');args=ap.parse_args()
    rows,evidence=calculate(args.value_density)
    suffix='' if args.value_density=='concentrated' else '_diffuse'
    write_rows(ROOT/f'bridge_results{suffix}.csv',rows)
    (ROOT/f'bridge_evidence{suffix}.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    summary={'value_density':args.value_density,'n':len(rows),'cisa_records':sum(r['cisa'] for r in rows),'complete_technical_inputs':sum(e['complete_technical_inputs'] for e in evidence),'safety_sensitive_with_complete_inputs':sum(r['psi_decides'] for r in rows),'unknown_technical_records':sum(not e['complete_technical_inputs'] for e in evidence)}
    (ROOT/f'bridge_summary{suffix}.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
