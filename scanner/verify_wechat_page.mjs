/** Execute the shipped page JS with API adapters; HTTP calls use real APK JNI.
 * This is NOT a WeChat runtime, device-camera or rendering acceptance test. */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const out=path.join(root,'output/camscanner-reverse');
const fixtureRoot=path.join(root,'.work/wechat-page-fixtures');
const code=fs.readFileSync(path.join(root,'scanner/wechat-miniprogram/pages/scan/index.js'),'utf8');
const sha=data=>crypto.createHash('sha256').update(data).digest('hex');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const ab=data=>data.buffer.slice(data.byteOffset,data.byteOffset+data.byteLength);
const records=[];
const gatewayBase=process.env.SCANNER_TEST_BASE||'http://127.0.0.1:18766';

function loadPage({live=false,curve=false}={}){
  let definition;const requests=[],pending=[],writes=[],draws=[],cameraCalls=[];
  const canvas={getContext(){return ctx}};
  const ctx={scale(){},clearRect(){draws.push({clear:true})},beginPath(){this.points=[]},
    moveTo(x,y){this.points.push([x,y])},lineTo(x,y){this.points.push([x,y])},closePath(){},
    stroke(){draws.push({color:this.strokeStyle,points:this.points})}};
  const wx={env:{USER_DATA_PATH:'/mock-local'},getWindowInfo:()=>({pixelRatio:2}),
    createSelectorQuery(){return {select(){return this},fields(){return this},exec(fn){fn([{node:canvas,width:360,height:480}])}}},
    createCameraContext(){return {onCameraFrame(){return {start(){},stop(){}}},takePhoto(options){cameraCalls.push(Date.now());queueMicrotask(()=>options.success({tempImagePath:'camera.jpg'}))}}},
    getFileSystemManager(){return {readFile(options){queueMicrotask(()=>options.success({data:ab(fs.readFileSync(path.join(root,'scanner/samples/photo-1.jpg')))}))},
      writeFile(options){writes.push(Buffer.from(options.data));queueMicrotask(()=>options.success())}}},
    request(options){
      const controller=new AbortController();let finish;
      const task={aborted:false,abort(){this.aborted=true;controller.abort()},done:new Promise(resolve=>{finish=resolve})};
      const record={route:new URL(options.url).pathname,started:Date.now(),options,task};requests.push(record);
      if(!live){pending.push(record);return task}
      (async()=>{
        try{
          const response=await fetch(options.url,{method:options.method||'GET',headers:options.header,body:options.data,signal:controller.signal});
          const data=options.responseType==='arraybuffer'?await response.arrayBuffer():await response.json();
          record.status=response.status;record.data=data;options.success?.({statusCode:response.status,data});
        }catch(error){record.error=error.message;options.fail?.({errMsg:error.message})}
        finally{record.finished=Date.now();options.complete?.();finish()}
      })();return task;
    }};
  vm.runInNewContext(code,{Page:value=>{definition=value},require:()=>({baseUrl:gatewayBase,curveBorder:curve}),wx,Date,setTimeout,clearTimeout},{filename:'wechat/pages/scan/index.js'});
  const page={...definition,data:structuredClone(definition.data),setData(values){Object.assign(this.data,values)}};
  page.onLoad();return {page,requests,pending,writes,draws,cameraCalls,ctx};
}
async function check(name,fn){try{const evidence=await fn();records.push({name,passed:true,...evidence})}catch(error){records.push({name,passed:false,error:error.stack})}}

await check('live page frames and queued shutter -> original Android JNI',async()=>{
  const adb=path.join(root,'.work/android-sdk/platform-tools/adb.exe');
  const device=(...args)=>execFileSync(adb,['-s','emulator-5580',...args],{encoding:'utf8'}).trim();
  device('shell','am','force-stop','org.localresearch.scanner');
  device('shell','am','start','-n','org.localresearch.scanner/.MainActivity','--es','stage','http-server');
  const deadline=Date.now()+20000;
  while(true){try{const response=await fetch(gatewayBase+'/health');if(response.ok&&(await response.json()).status==='ready')break}catch{}
    if(Date.now()>deadline)throw Error('Original Android service unavailable');await delay(250)}
  const h=loadPage({live:true});h.page.onReady();await h.requests.at(-1).task.done;assert.equal(h.page.data.ready,true);h.page.cameraReady();
  const statuses=[],colors=[];
  const sequence=[...Array(13).fill('stable'),...Array(12).fill('blank'),...Array(13).fill('stable'),...Array(4).fill('shift'),...Array(3).fill('blank')];
  for(const kind of sequence){
    const data=ab(fs.readFileSync(path.join(fixtureRoot,kind+'.rgba')));h.page.lastFrame=Date.now()-401;
    const before=h.requests.length;h.page.frame({data,width:480,height:360});h.page.frame({data,width:480,height:360});
    assert.equal(h.requests.length,before+1,'Single request while detection pending');
    await h.requests.at(-1).task.done;
    const result=h.requests.at(-1).data;assert.equal(h.requests.at(-1).status,200);statuses.push(result.native_status);
    colors.push(h.draws.at(-1).color||'hidden');
  }
  // Restored AutoDrawBorderHandle initializes capacity=11 outside sandbox.
  // The old capacity=7 expectation must not be used for the current harness.
  assert.deepEqual(statuses.slice(0,13),[...Array(11).fill(3),1,1]);
  const blankStatuses=statuses.slice(13,25);
  assert.deepEqual(colors.slice(0,13),[...Array(11).fill('#ffce68'),'#6ff0bc','#6ff0bc']);
  for(let i=0;i<statuses.length;i++)if(statuses[i]===2)assert.equal(colors[i],'hidden');
  assert.ok(statuses.slice(-3).includes(2),'Shift/removal fixture exercises native fallback and page hide');
  const data=ab(fs.readFileSync(path.join(fixtureRoot,'stable.rgba')));h.page.lastFrame=Date.now()-401;
  h.page.frame({data,width:480,height:360});const detector=h.requests.at(-1);h.page.capture();
  const until=Date.now()+15000;while(h.page.data.processing&&Date.now()<until)await delay(50);
  assert.equal(h.page.data.processing,false);assert.equal(h.page.data.pages.length,1);
  assert.ok(h.cameraCalls[0]>=detector.finished,'Shutter waits for native detector completion');
  assert.equal(h.writes.length,1);const expected=fs.readFileSync(path.join(out,'model-probe/photo-1-android-adapter-scan.png'));
  assert.equal(sha(h.writes[0]),sha(expected));assert.ok(h.requests.every(r=>r.status===200));
  const installed=device('shell','pm','path','org.localresearch.scanner').replace('package:','');
  return {frame_sequence:sequence,native_statuses:statuses,blank_after_stable:blankStatuses,blank_after_shift:statuses.slice(-3),outline_colors:colors,scan_sha256:sha(h.writes[0]),scan_matches_direct_adapter:true,
    harness_apk_sha256:device('shell','sha256sum',installed).split(/\s/)[0],scope:'Actual page JS, wx transport/camera/canvas adapters in Node; original native HTTP backend real. Synthetic camera frames/JPEG; no real WeChat rendering/capture.'};
});
await check('curve page route and 80-point contour use actual original JNI',async()=>{
  const h=loadPage({live:true,curve:true});h.page.onReady();await h.requests.at(-1).task.done;assert.equal(h.page.data.ready,true);
  h.page.cameraReady();const observed=[];
  for(const kind of ['stable','blank','stable']){
    h.page.lastFrame=0;h.page.frame({data:ab(fs.readFileSync(path.join(fixtureRoot,kind+'.rgba'))),width:480,height:360});
    const request=h.requests.at(-1);assert.equal(request.route,'/detect-curve-rgba');await request.task.done;
    assert.equal(request.status,200);const r=request.data;observed.push({fixture:kind,native_status:r.native_status,curve_length:r.curve.length});
    if(kind==='blank'){assert.equal(r.curve.length,0);assert.equal(h.draws.at(-1).clear,true)}
    else {
      assert.equal(r.curve.length,160);const drawn=h.draws.at(-1);assert.equal(drawn.points.length,80);
      const scale=Math.max(360/r.width,480/r.height),left=(360-r.width*scale)/2,top=(480-r.height*scale)/2;
      assert.equal(drawn.points[0][0],left+r.curve[0]*scale);assert.equal(drawn.points[79][1],top+r.curve[159]*scale);
    }
  }
  return {observed,scope:'Actual page JS and gateway/JNI; wx/camera/canvas APIs adapted in Node, not a real WeChat client.'};
});
await check('late scan callback after hide/show cannot append a stale page',async()=>{
  const h=loadPage();h.page.data.processing=true;h.page.scan(new ArrayBuffer(1));const request=h.pending.at(-1);
  h.page.onHide();h.page.onShow();request.options.success({statusCode:200,data:new ArrayBuffer(1)});
  await delay(0);assert.equal(request.task.aborted,true);assert.equal(h.page.data.pages.length,0);assert.equal(h.page.data.processing,false);
  return {scope:'Deterministic delayed platform callback after cancellation; wx APIs simulated'};
});
await check('late health callback after hide cannot enable shutter',()=>{
  const h=loadPage();h.page.onReady();const request=h.pending.at(-1);h.page.onHide();
  request.options.success({statusCode:200,data:{status:'ready'}});assert.equal(request.task.aborted,true);assert.equal(h.page.data.ready,false);
  return {scope:'Deterministic delayed platform callback; wx APIs simulated'};
});
await check('request throttle, cancelled detector and return to page',()=>{
  const h=loadPage();h.page.data.ready=true;const frame={data:new ArrayBuffer(480*360*4),width:480,height:360};
  h.page.lastFrame=Date.now();h.page.frame(frame);assert.equal(h.requests.length,0);
  h.page.lastFrame=0;h.page.frame(frame);const request=h.pending.at(-1);assert.equal(h.requests.length,1);
  h.page.onHide();h.page.onShow();const health=h.pending.at(-1);assert.equal(request.task.aborted,true);
  health.options.success({statusCode:200,data:{status:'ready'}});assert.equal(h.page.data.ready,true);
  const before=JSON.stringify(h.page.data);
  request.options.success({statusCode:200,data:{quad:[0,0,480,0,480,360,0,360],width:480,height:360,stable:true}});
  request.options.complete();assert.equal(JSON.stringify(h.page.data),before);assert.equal(h.page.busy,false);
  return {scope:'Actual page handlers, deterministic delayed transport callbacks; frame throttling uses real clock'};
});
await check('hide before takePhoto callback cannot queue an image upload',async()=>{
  const h=loadPage();h.page.cameraReady();h.page.data.ready=true;h.page.capture();h.page.onHide();h.page.onShow();
  await delay(0);assert.equal(h.requests.some(r=>r.route==='/scan'),false);assert.equal(h.page.data.processing,false);
  return {scope:'Simulated delayed camera callback; no physical-camera claim'};
});
const report={page_js_sha256:sha(code),records,scope:'Node execution of actual mini-program page code. Only live fixture uses real original Android JNI. This does not prove WeChat runtime, camera orientation, native component/canvas placement, AppID or network-domain acceptance.'};
fs.writeFileSync(path.join(out,'wechat-page-integration-evidence.json'),JSON.stringify(report,null,2));
console.log(JSON.stringify(report,null,2));if(records.some(r=>!r.passed))process.exitCode=1;
