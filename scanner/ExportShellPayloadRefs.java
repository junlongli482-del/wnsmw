import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportShellPayloadRefs extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();LinkedHashSet<Function> functions=new LinkedHashSet<>();
        try(PrintWriter out=new PrintWriter(new File(args[0]),StandardCharsets.UTF_8)) {
            out.println("Reconstructed offline memory image: "+currentProgram.getName());
            out.println("SHA256: "+currentProgram.getExecutableSHA256());
            out.println("Reference coverage depends on Ghidra analysis; no complete runtime coverage or original source claim.");
            for(int i=1;i<args.length;i++) {
                Address address=currentProgram.getImageBase().add(Long.parseLong(args[i],16));
                out.println("\nDATA "+address);
                for(Reference ref:getReferencesTo(address)) {
                    Function f=getFunctionContaining(ref.getFromAddress());
                    out.println(ref+" function="+(f==null?"unknown":f.getEntryPoint()));
                    if(f!=null)functions.add(f);
                }
            }
            DecompInterface decompiler=new DecompInterface();decompiler.openProgram(currentProgram);
            try {
                for(Function f:functions) {
                    out.println("\nFUNCTION "+f.getName()+" @ "+f.getEntryPoint());
                    DecompileResults result=decompiler.decompileFunction(f,35,monitor);
                    if(result.decompileCompleted())out.println(result.getDecompiledFunction().getC());
                    else out.println(result.getErrorMessage());
                }
            }finally{decompiler.dispose();}
        }
    }
}
