/** Local research gateway to the original Android JNI over adb forwarding. */
import http from 'node:http';
import { performance } from 'node:perf_hooks';

const host=process.env.SCANNER_BIND_HOST||'127.0.0.1';
const port=Number(process.env.SCANNER_GATEWAY_PORT||18766);
const androidPort=Number(process.env.SCANNER_ANDROID_PORT||18765);
const maxBody=32*1024*1024;
let occupied=false;
const server=http.createServer(async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  if(!['/health','/detect','/detect-rgba','/detect-curve','/detect-curve-rgba','/scan'].includes(req.url)||!['GET','POST'].includes(req.method)){
    res.writeHead(404);res.end();return;
  }
  if(occupied){res.writeHead(429,{'Content-Type':'application/json'});res.end(JSON.stringify({error:'原库正在处理上一请求'}));req.resume();return;}
  occupied=true;
  try{
    const buffers=[];let count=0;const started=performance.now();
    for await(const chunk of req){count+=chunk.length;if(count>maxBody)throw new Error('Image exceeds 32 MiB');buffers.push(chunk);}
    const body=Buffer.concat(buffers);
    const headers={'content-length':String(body.length),'content-type':req.headers['content-type']||'application/octet-stream'};
    for(const key of ['x-frame-width','x-frame-height'])if(req.headers[key])headers[key]=req.headers[key];
    const result=await fetch(`http://127.0.0.1:${androidPort}${req.url}`,{method:req.method,headers,
      ...(req.method==='POST'?{body}:{}),signal:AbortSignal.timeout(req.url==='/scan'?120000:15000)});
    const output=Buffer.from(await result.arrayBuffer());
    res.writeHead(result.status,{'Content-Type':result.headers.get('content-type')||'application/octet-stream','Content-Length':output.length,'X-Gateway-Ms':String(Math.round(performance.now()-started))});res.end(output);
  }catch(error){if(!res.headersSent)res.writeHead(502,{'Content-Type':'application/json'});res.end(JSON.stringify({error:error.message}));}
  finally{occupied=false;}
});
server.headersTimeout=10000;server.requestTimeout=130000;
server.listen(port,host,()=>console.log(`Research JNI gateway http://${host}:${port}; Android localhost:${androidPort}`));
