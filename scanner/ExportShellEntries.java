import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Analysis of reconstructed memory images only; does not modify original artifacts.
public class ExportShellEntries extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        LinkedHashSet<Function> selected=new LinkedHashSet<>();
        try(PrintWriter out=new PrintWriter(new File(args[0]),StandardCharsets.UTF_8)) {
            out.println("Input: "+currentProgram.getName());
            out.println("SHA256: "+currentProgram.getExecutableSHA256());
            out.println("Language: "+currentProgram.getLanguageID()+" base="+currentProgram.getImageBase());
            out.println(currentProgram.getName().contains("constructors")
                ? "Reconstructed constructor memory: ELF relocations applied by emulator; import pointers reference documented emulator stubs outside this image. Static pseudocode is not original source."
                : "Reconstructed DT_INIT memory: relocations/imports not applied. Static pseudocode is not original source.");
            for(int i=1;i<args.length;i++) {
                Address entry=currentProgram.getImageBase().add(Long.parseLong(args[i],16));
                disassemble(entry);
                Function f=getFunctionAt(entry);
                if(f==null) f=getFunctionContaining(entry);
                if(f==null) f=createFunction(entry,"shell_entry_"+args[i]);
                // JNI specifies jint JNI_OnLoad(JavaVM*, void*). Without callers,
                // inference can discard the pop helper's EAX return as void.
                if(f!=null && f.getName().equals("JNI_OnLoad")) {
                    f.setCallingConvention("__cdecl");
                    f.setReturnType(IntegerDataType.dataType,SourceType.USER_DEFINED);
                    f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,
                        SourceType.USER_DEFINED,
                        new ParameterImpl("vm",new PointerDataType(VoidDataType.dataType),currentProgram),
                        new ParameterImpl("reserved",new PointerDataType(VoidDataType.dataType),currentProgram));
                }
                // Exact descriptors recovered from original RegisterNatives execution
                // in the documented offline JNI model (not an ART runtime trace).
                long offset=Long.parseLong(args[i],16);
                String[] nativeNames=null;
                DataType returnType=null;
                DataType ptr=new PointerDataType(VoidDataType.dataType);
                if(offset==0x6f870 || offset==0x729e0 || offset==0x73310) {
                    nativeNames=new String[]{"env","clazz","application","name"};
                    returnType=ByteDataType.dataType;
                } else if(offset==0x73520) {
                    nativeNames=new String[]{"env","clazz","classLoader","applicationInfo","packageName","originalAppName"};
                    returnType=ptr;
                } else if(offset==0x734f0) {
                    nativeNames=new String[]{"env","clazz","bytes","mode"};returnType=ptr;
                } else if(offset==0x73500) {
                    nativeNames=new String[]{"env","clazz","name","mode"};returnType=VoidDataType.dataType;
                } else if(offset==0x73510) {
                    nativeNames=new String[]{"env","clazz","first","second"};returnType=VoidDataType.dataType;
                } else if(offset==0x7dc60) {
                    nativeNames=new String[]{"env","clazz","text"};returnType=ptr;
                }
                if(f!=null && nativeNames!=null) {
                    f.setCallingConvention("__cdecl");
                    f.setReturnType(returnType,SourceType.USER_DEFINED);
                    ParameterImpl[] params=new ParameterImpl[nativeNames.length];
                    for(int p=0;p<params.length;p++) params[p]=new ParameterImpl(nativeNames[p],
                        nativeNames[p].equals("mode")?IntegerDataType.dataType:ptr,currentProgram);
                    f.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,true,SourceType.USER_DEFINED,params);
                }
                if(f!=null) selected.add(f); else out.println("Cannot create function at "+entry);
            }
            for(Function f:new ArrayList<Function>(selected)) selected.addAll(f.getCalledFunctions(monitor));
            DecompInterface decompiler=new DecompInterface();decompiler.openProgram(currentProgram);
            try {
                for(Function f:selected) {
                    if(f.isExternal()) continue;
                    out.println("\nFUNCTION "+f.getName()+" @ "+f.getEntryPoint());
                    out.println("CALLS "+f.getCalledFunctions(monitor));
                    DecompileResults result=decompiler.decompileFunction(f,35,monitor);
                    if(result.decompileCompleted()) out.println(result.getDecompiledFunction().getC());
                    else out.println("UNAVAILABLE: "+result.getErrorMessage());
                    out.flush();
                }
            } finally { decompiler.dispose(); }
        }
    }
}
