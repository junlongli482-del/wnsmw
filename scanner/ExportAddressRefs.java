import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.listing.Function;
import ghidra.app.decompiler.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
public class ExportAddressRefs extends GhidraScript {
    public void run() throws Exception {
        String[] a=getScriptArgs();
        DecompInterface d=new DecompInterface();d.openProgram(currentProgram);
        LinkedHashSet<Function> funcs=new LinkedHashSet<>();
        try(PrintWriter w=new PrintWriter(new File(a[0]),StandardCharsets.UTF_8)) {
            for(int i=1;i<a.length;i++) {
                Address target=toAddr(a[i]);w.println("TARGET "+target);
                ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(target);
                while(refs.hasNext()) {
                    Reference r=refs.next();Function f=currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                    w.println(r+" FUNCTION "+(f==null?"unknown":f.getName()));if(f!=null)funcs.add(f);
                }
            }
            for(Function f:funcs) {
                w.println("FUNCTION "+f.getName()+" @ "+f.getEntryPoint());
                DecompileResults r=d.decompileFunction(f,45,monitor);
                if(r.decompileCompleted())w.println(r.getDecompiledFunction().getC());
            }
        }
        d.dispose();
    }
}
