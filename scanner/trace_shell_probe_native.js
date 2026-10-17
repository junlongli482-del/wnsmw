// Passive native-only trace for the separate x86 shell probe. No return replacement.
const installed=new Set();
function str(p){try{return p.isNull()?null:p.readUtf8String();}catch(_){return '<unreadable>';}}
function hookModule(module, suppliedEntry){
  if(installed.has(module.base.toString()))return;
  installed.add(module.base.toString());
  const entry=suppliedEntry || module.findExportByName('JNI_OnLoad');
  send({event:'shell_module',name:module.name,base:module.base.toString(),size:module.size,jni:entry?.toString()||null});
  if(!entry)return;
  Interceptor.attach(entry,{
    onEnter(args){
      this.worker=Process.getCurrentThreadId();
      send({event:'JNI_OnLoad_enter',module:module.name,thread:this.worker});
      try{
        const vm=args[0],out=Memory.alloc(Process.pointerSize);
        const getEnv=new NativeFunction(vm.readPointer().add(6*Process.pointerSize).readPointer(),'int',['pointer','pointer','int']);
        const status=getEnv(vm,out,0x10004);
        send({event:'probe_GetEnv',status,scope:'Actual JavaVM GetEnv for already attached thread'});
        if(status!==0)return;
        const table=out.readPointer().readPointer(),worker=this.worker;
        const operations={6:'FindClass',33:'GetMethodID',113:'GetStaticMethodID',144:'GetStaticFieldID',215:'RegisterNatives'};
        for(const [index,name] of Object.entries(operations)){
          const address=table.add(Number(index)*Process.pointerSize).readPointer();
          Interceptor.attach(address,{
            onEnter(a){
              if(Process.getCurrentThreadId()!==worker)return;
              const event={event:'JNI',operation:name};
              if(name==='FindClass')event.className=str(a[1]);
              else if(name==='RegisterNatives'){
                const count=a[3].toInt32();event.count=count;event.methods=[];
                if(count>=0&&count<=512)for(let i=0;i<count;i++){
                  const row=a[2].add(i*3*Process.pointerSize),fn=row.add(2*Process.pointerSize).readPointer();
                  event.methods.push({name:str(row.readPointer()),signature:str(row.add(Process.pointerSize).readPointer()),function:fn.toString(),offset:fn.sub(module.base).toString()});
                }
              }else{event.name=str(a[2]);event.signature=str(a[3]);}
              send(event);
            }
          });
        }
      }catch(e){send({event:'probe_error',error:String(e)});}
    },
    onLeave(result){
      const event={event:'JNI_OnLoad_return',module:module.name,result:result.toString()};
      if(module.name==='libexec.so')try{
        const state=module.base.add(0x12dff0);event.state=state.toString();
        event.stateWords=Array.from({length:40},(_,i)=>state.add(i*4).readU32());
      }catch(e){event.stateError=String(e);}
      send(event);
    }
  });
}
Interceptor.attach(Module.getGlobalExportByName('android_dlopen_ext'),{
  onEnter(args){this.path=str(args[0]);},
  onLeave(result){
    if(!this.path||! /\/libexec(main)?\.so$/.test(this.path))return;
    send({event:'shell_dlopen_return',path:this.path,result:result.toString()});
    if(!result.isNull()){
      // The shell may hide its module from enumeration. Use the same actual
      // handle/symbol lookup that ART uses; no handle or return is substituted.
      const lookup=new NativeFunction(Module.getGlobalExportByName('dlsym'),'pointer',['pointer','pointer']);
      const entry=lookup(result,Memory.allocUtf8String('JNI_OnLoad'));
      send({event:'actual_dlsym',name:'JNI_OnLoad',address:entry.toString()});
      if(!entry.isNull()&&this.path.endsWith('/libexec.so'))
        hookModule({name:'libexec.so',base:entry.sub(0x6e280),size:0x130000},entry);
    }
  }
});
for(const name of ['exit','_exit','abort','kill','tgkill'])try{
  Interceptor.attach(Module.getGlobalExportByName(name),{onEnter(args){send({event:'termination',name,args:[args[0].toString(),args[1].toString(),args[2].toString()]});}});
}catch(_){}
send({event:'ready',arch:Process.arch,scope:'Passive real JNI trace in separate x86 research package, no return replacement'});
