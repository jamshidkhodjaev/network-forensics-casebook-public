#!/usr/bin/env python3
"""Read-only optional PCAP corroboration. No acquisition, body export or execution.

Validates the public selection against independently supplied evidence. Does not
reproduce private export hashes or inspect endpoint execution.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
from casebook import ROOT, TIMELINE, require, digest, utc, redact_host, decode, read_csv


def run(command):
    result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8')
    require(result.returncode==0,'TShark failed: '+result.stderr.strip())
    return result.stdout


def verify(pcap,tshark):
    require(pcap.is_file(),'Missing local evidence: supply an independently obtained PCAP with --pcap')
    meta=json.loads((ROOT/'data/provenance.json').read_text())
    require(digest(pcap)==meta['pcap_sha256'],'PCAP hash mismatch')
    version=run([tshark,'--version']).splitlines()[0]
    require('4.6.9' in version,'Reference reproduction requires TShark 4.6.9')
    specs=json.loads((ROOT/'data/packet-checks.json').read_text())
    fields=sorted({'frame.number','frame.time_epoch','http.file_data','http.content_length'}|{f for spec in specs.values() for f in spec})
    available={p[2] for line in run([tshark,'-G','fields']).splitlines() if len(p:=line.split('\t'))>=3 and p[0]=='F'}
    require(set(fields)<=available,'Unsupported TShark field')
    count=run([tshark,'-n','-r',str(pcap),'-T','fields','-e','frame.number']).splitlines()
    require(count==[str(i) for i in range(1,meta['packet_count']+1)],'Packet count/order mismatch')
    cmd=[tshark,'-n','-2','-r',str(pcap),'-Y','frame.number in {'+','.join(sorted(specs,key=int))+'}','-T','json']
    for field in fields:cmd+=['-e',field]
    packets=json.loads(run(cmd))
    actual={p['_source']['layers']['frame.number'][0]:p['_source']['layers'] for p in packets}
    require(set(actual)==set(specs),'Missing selected packet')
    timeline=read_csv(ROOT/'evidence/timeline.csv',TIMELINE)
    for row in timeline:
        n=row['packet_number'];layers=actual[n]
        require(utc(layers['frame.time_epoch'][0])==row['timestamp_utc'],'UTC mismatch at P'+n)
        for field,expected in specs[n].items():
            value=','.join(layers.get(field,[]))
            if field in {'dns.qry.name','http.host','tls.handshake.extensions_server_name'}:value=redact_host(value)
            if field=='http.request.uri':value=value.split('?')[0]
            require(value==expected,'Public field mismatch at P'+n+': '+field)
    bodies={}
    for n,length in {'6151':2761,'7330':4911,'7639':2329,'8064':4399,'8194':8304}.items():
        raw=bytes.fromhex(actual[n]['http.file_data'][0])
        require(len(raw)==length==int(actual[n]['http.content_length'][0]),'Response body length mismatch')
        bodies[n]=raw.decode('utf-8')
    for n in ['6151','7330','7639']:
        require("document.createElement('script')" in bodies[n] and 'insertBefore(s,sc)' in bodies[n],'Script insertion not found')
    require(all(s in bodies['7330'] for s in ['n.userAgent','s.width','n.language','navigator.plugins','WEBGL_debug_renderer_info']),'Collection logic missing')
    landing=bodies['8064']
    require(all(s in landing for s in ['Update Chrome','Your download will begin automatically','3000','buttonDownload','window.location.href = fileUrl']),'Lure logic missing')
    for source,target in [('6151','6424'),('7330','7343'),('7639','7871')]:
        targets=[decode(s) for s in re.findall(r"getUrl\('([^'\\]*)'\)",bodies[source])]
        from urllib.parse import urlsplit
        require(any(urlsplit(url).netloc==actual[target]['http.host'][0] and actual[target]['http.request.uri'][0].startswith(urlsplit(url).path+'?'+urlsplit(url).query) for url in targets),'Decoded chain mismatch')
    target=re.findall(r"getUrl\('([^'\\]*)'\)",landing)
    require(len(target)==1 and decode(target[0]).endswith('/Chrome_72.3.22.js?dl=1'),'Intended filename mismatch')
    require(digest(pcap)==meta['pcap_sha256'],'Source changed')
    return {'selected_packets_verified':len(actual),'body_checks':5,'source_hash_unchanged':True,'outcome':'download and execution unconfirmed'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap',required=True,type=Path)
    parser.add_argument('--tshark',default='tshark')
    args=parser.parse_args()
    try:print(json.dumps(verify(args.pcap,args.tshark),sort_keys=True))
    except (OSError,ValueError,KeyError) as exc:parser.exit(1,f'ERROR: {exc}\n')
