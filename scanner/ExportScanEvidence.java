// Read-only analysis of a temporary imported copy; exports selected decompiler evidence.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportScanEvidence extends GhidraScript {
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        File destination = new File(arguments[0]);
        destination.mkdirs();
        String pattern = arguments.length > 1 ? arguments[1] : "documentCrop|cardCut|SinglePageSet|adjustCorners|DetectCardInVideo|DetectBoundInVideo|DetectBoundLinesColor|EnhanceColorImageByModes|deshadow|initDeshadow|scanet|DetectFrameBorder|DetectBorderYUV|pagescan::InferNet|findLines_EDLine";
        // Android armeabi uses the base AAPCS interface even when VFP instructions exist.
        // Preserve old exports; explicitly request corrected call storage in new exports.
        if (arguments.length > 3 && arguments[3].equals("softfp")) {
            FunctionIterator all = currentProgram.getFunctionManager().getFunctions(true);
            while (all.hasNext()) all.next().setCallingConvention("__stdcall_softfp");
            FunctionIterator external = currentProgram.getFunctionManager().getExternalFunctions();
            while (external.hasNext()) external.next().setCallingConvention("__stdcall_softfp");
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        LinkedHashSet<Function> selected = new LinkedHashSet<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (java.util.regex.Pattern.compile(pattern).matcher(function.getSymbol().getName(true)).find() && !function.isExternal() && !function.isThunk())
                selected.add(function);
        }
        LinkedHashSet<Function> direct = new LinkedHashSet<>();
        for (Function function : selected) direct.addAll(function.getCalledFunctions(monitor));
        selected.addAll(direct);
        String suffix = arguments.length > 2 ? arguments[2] : "decompiled";
        File output = new File(destination, currentProgram.getName()+"-"+suffix+".txt");
        try (PrintWriter writer = new PrintWriter(output, StandardCharsets.UTF_8)) {
            writer.println("Program: "+currentProgram.getName());
            writer.println("SHA256: "+currentProgram.getExecutableSHA256());
            writer.println("Language: "+currentProgram.getLanguageID());
            writer.println("Selected functions and one direct callee layer. Static evidence, not original source or proof of runtime execution.");
            int count = 0;
            for (Function function : selected) {
                if (monitor.isCancelled()) break;
                String fullName = function.getSymbol().getName(true);
                if (function.isExternal() || function.isThunk() || fullName.startsWith("std::") || fullName.startsWith("cv::")) continue;
                if (++count > 120) { writer.println("TRUNCATED: 120-function budget"); break; }
                writer.println("\nFUNCTION "+fullName+" @ "+function.getEntryPoint());
                writer.println("CALLS "+function.getCalledFunctions(monitor));
                DecompileResults result = decompiler.decompileFunction(function, 35, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction()!=null)
                    writer.println(result.getDecompiledFunction().getC());
                else writer.println("UNAVAILABLE: "+result.getErrorMessage());
                writer.flush();
            }
        } finally { decompiler.dispose(); }
        println("Exported "+output);
    }
}
