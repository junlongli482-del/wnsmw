import Java from '../.work/rea-tools/frida-java-bridge/package/index.js';
import './trace_android_loader.js';
// Disabled by default. The separate controlled build explicitly enables ABI
// substitution and logs every replacement; it is not an unmodified app trace.
const substituteArm = globalThis.REA_ARM_COMPAT === true;
send({event:'java_bridge_ready',available:Java.available});
Java.performNow(() => {
  const Runtime=Java.use('java.lang.Runtime');
  for (const method of ['load0','loadLibrary0']) {
    if (!Runtime[method]) continue;
    for (const overload of Runtime[method].overloads) {
      overload.implementation=function (...args) {
        const rendered=args.map(x=>x===null?null:String(x));
        send({event:'java_load_enter',method,args:rendered});
        if (substituteArm && method==='load0' && args.length===2) {
          const path=String(args[1]);
          if (path.endsWith('/libexec.so') || path.endsWith('/libexecmain.so')) {
            const replacement=path.replace(/\/libexec(main)?\.so$/, '/rea-arm-libexec$1.so');
            send({event:'controlled_abi_substitution',original:path,replacement});
            args[1]=replacement;
          }
        }
        try {
          const result=overload.call(this,...args);
          send({event:'java_load_return',method,args:rendered});return result;
        } catch(e) {
          send({event:'java_load_throw',method,args:rendered,error:String(e)});throw e;
        }
      };
    }
  }
  send({event:'java_hooks_installed'});
});
