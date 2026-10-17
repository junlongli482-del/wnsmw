import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class ExportFunctionCallers extends GhidraScript {
  public void run() throws Exception {
    String[] a=getScriptArgs();
    try(PrintWriter out=new PrintWriter(new File(a[0]),StandardCharsets.UTF_8)) {
      for(int i=1;i<a.length;i++) {
        Address x=currentProgram.getImageBase().add(Long.parseLong(a[i],16));
        Function target=getFunctionContaining(x);
        out.println("TARGET "+x+" "+(target==null?"":target.getName()));
        for(Reference r: getReferencesTo(x)) {
          Function f=getFunctionContaining(r.getFromAddress());
          out.println("REF "+r+" CALLER "+(f==null?"unknown":f.getEntryPoint()+" "+f.getName()));
        }
        for(Reference r: getReferencesTo(x)) {
          Function f=getFunctionContaining(r.getFromAddress());
          if(f!=null) {
            for(var sr: f.getBody().getAddresses(true)) {
              // emit nearby defined strings through references from the caller body
              for(var ref: getReferencesFrom(sr)) {
                if(ref.getToAddress()!=null && getDataAt(ref.getToAddress())!=null)
                  out.println("DATAREF "+ref.getToAddress()+" IN "+f.getEntryPoint());
              }
            }
          }
        }
      }
    }
  }
}
