// Controlled ABI-path substitution only. Does not alter the APK or native code.
// Keep native Interceptor hooks out to isolate translation/loader failures.
import Java from '../.work/rea-tools/frida-java-bridge/package/index.js';
send({event:'probe_ready', java:Java.available, architecture:Process.arch});
Java.performNow(() => {
  const Runtime=Java.use('java.lang.Runtime');
  for (const overload of Runtime.load0.overloads) {
    overload.implementation=function (...args) {
      const original=args.map(x=>x===null?null:String(x));
      if (args.length===2 && /\/libexec(main)?\.so$/.test(String(args[1]))) {
        args[1]=String(args[1]).replace(/\/libexec(main)?\.so$/, '/rea-arm-libexec$1.so');
        send({event:'controlled_abi_substitution',original:original[1],replacement:String(args[1])});
      }
      send({event:'load_enter',args:args.map(String)});
      try { const r=overload.call(this,...args); send({event:'load_return',original}); return r; }
      catch(e) { send({event:'load_throw',original,error:String(e)}); throw e; }
    };
  }
  send({event:'java_hooks_installed'});
});
let samples=0;
const timer=setInterval(() => {
  const threads=Process.enumerateThreads().map(t=>({id:t.id,name:t.name,state:t.state,
    pc:t.context.pc.toString(), module:Process.findModuleByAddress(t.context.pc)?.name || null}));
  send({event:'thread_sample',sample:++samples,threads});
  if (samples>=4) clearInterval(timer);
}, 2000);
