// Observe loading and JNI registration only; no return values are replaced.
const attached = new Set();
function report(event, details) { send({event, ...details}); }
function cstr(p) { try { return p.isNull() ? null : p.readUtf8String(); } catch (_) { return '<unreadable>'; } }
for (const name of ['dlopen', 'android_dlopen_ext', 'dlerror']) {
  try {
    const address = Module.getGlobalExportByName(name);
    Interceptor.attach(address, {
      onEnter(args) { this.path = name === 'dlerror' ? null : cstr(args[0]); },
      onLeave(result) {
        report(name, {path: this.path, result: result.toString(), error: name === 'dlerror' ? cstr(result) : null});
      }
    });
    report('hook_installed', {name, address: address.toString()});
  } catch (e) { report('hook_unavailable', {name, error: String(e)}); }
}
try {
  const art = Process.getModuleByName('libart.so');
  for (const symbol of art.enumerateSymbols()) {
    if (symbol.name.includes('ThrowNew') && symbol.name.includes('JNI') && !attached.has(symbol.address.toString())) {
      attached.add(symbol.address.toString());
      Interceptor.attach(symbol.address, {onEnter(args) { report('ThrowNew', {symbol: symbol.name, message: cstr(args[2])}); }});
    }
    if (!symbol.name.includes('RegisterNatives') || symbol.name.includes('CheckJNI') || attached.has(symbol.address.toString())) continue;
    attached.add(symbol.address.toString());
    Interceptor.attach(symbol.address, {
      onEnter(args) {
        const count = args[3].toInt32();
        if (count < 0 || count > 1024) return;
        const methods = [];
        for (let i = 0; i < count; i++) {
          try {
            const row = args[2].add(i * Process.pointerSize * 3);
            const fn = row.add(Process.pointerSize * 2).readPointer();
            const module = Process.findModuleByAddress(fn);
            methods.push({name: cstr(row.readPointer()), signature: cstr(row.add(Process.pointerSize).readPointer()), address: fn.toString(), module: module ? module.name : null});
          } catch (e) { methods.push({error: String(e)}); break; }
        }
        report('RegisterNatives', {symbol: symbol.name, methods});
      }
    });
    report('hook_installed', {name: symbol.name, address: symbol.address.toString()});
  }
} catch (e) { report('art_hook_error', {error: String(e)}); }
report('ready', {architecture: Process.arch, pointerSize: Process.pointerSize});
for (const mod of Process.enumerateModules()) {
  if (!/nativebridge|ndk_translation/.test(mod.name)) continue;
  const symbols=mod.enumerateSymbols().filter(x=>/LoadLibrary|LoadNative|JNI_OnLoad|Initialize|GetTrampoline/.test(x.name));
  report('native_bridge_symbols',{module:mod.name,symbols:symbols.map(x=>({name:x.name,address:x.address.toString()}))});
  for (const symbol of symbols) {
    if (!/LoadLibrary|LoadNativeBridgeLibrary/.test(symbol.name) || attached.has(symbol.address.toString())) continue;
    attached.add(symbol.address.toString());
    Interceptor.attach(symbol.address,{
      onEnter(args){this.path=cstr(args[0]);report('bridge_load_enter',{name:symbol.name,path:this.path});},
      onLeave(result){report('bridge_load_return',{name:symbol.name,path:this.path,result:result.toString()});}
    });
  }
}
