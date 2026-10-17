"""Read a focused restored DEX class through the installed JADX MCP engine."""
from pathlib import Path
import subprocess,json,threading,queue,sys,time
ROOT=Path(__file__).resolve().parents[1]
def main():
    number,cls,label=sys.argv[1:4]
    p=subprocess.Popen(['C:/Program Files/Amazon Corretto/jdk21.0.12_12/bin/java.exe','-Xmx2048m','-XX:ActiveProcessorCount=4','-jar',str(ROOT/'.work/rea-tools/jadx-verified.jar'),'--apk',str(ROOT/'output/camscanner-reverse/restored-business-dex'/('classes'+number+'.dex')),'--threads','1','--resources','none','--decompile-timeout-ms','45000'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8')
    q=queue.Queue()
    def reader():
        for line in p.stdout:
            try:q.put(json.loads(line))
            except ValueError:pass
    threading.Thread(target=reader,daemon=True).start()
    def call(i,method,params):
        p.stdin.write(json.dumps({'jsonrpc':'2.0','id':i,'method':method,'params':params})+'\n');p.stdin.flush()
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            r=q.get(timeout=max(0.1,deadline-time.monotonic()))
            if r.get('id')==i:return r
        raise TimeoutError(method)
    try:
        call(1,'initialize',{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'local-research','version':'1'}})
        p.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');p.stdin.flush()
        inventory=call(2,'tools/list',{})
        tool=next(x for x in inventory['result']['tools'] if x['name']=='get_class_source')
        response=call(3,'tools/call',{'name':tool['name'],'arguments':{'class_name':cls,'max_bytes':250000,'smali_fallback':False}})
        out=ROOT/'output/camscanner-reverse';(out/(label+'.json')).write_text(json.dumps({'tool_schema':tool,'response':response},indent=2),encoding='utf-8')
        for item in response.get('result',{}).get('content',[]):
            if item.get('type')=='text':
                value=item['text']
                try:
                    parsed=json.loads(value);value=parsed.get('source',parsed.get('code',value))
                except ValueError:pass
                value=value.replace('\r\n','\n').replace('\r','')
                (out/(label+'.java.txt')).write_text(value,encoding='utf-8')
                print(value[:18000])
    finally:p.terminate();p.wait(timeout=10)
if __name__=='__main__':main()
