package org.localresearch.stackprobe;
import android.app.AppComponentFactory;
import android.content.pm.ApplicationInfo;
import java.io.*;
import org.json.*;

/** Records a genuine framework factory/native/Thread stack; no original library. */
public final class ProbeFactory extends AppComponentFactory {
    private static native StackTraceElement[] captureStack();
    private static native int probeService(String name);
    private static native String probeDlopen(String name,int flags);
    @Override public ClassLoader instantiateClassLoader(ClassLoader loader,ApplicationInfo info) {
        try {
            System.load(info.nativeLibraryDir+"/libstackprobe.so");
            StackTraceElement[] frames=captureStack();
            JSONArray rows=new JSONArray();
            for(StackTraceElement frame:frames) {
                JSONObject row=new JSONObject();row.put("className",frame.getClassName());
                row.put("methodName",frame.getMethodName());row.put("fileName",frame.getFileName());
                row.put("lineNumber",frame.getLineNumber());rows.put(row);
            }
            JSONObject result=new JSONObject();result.put("captured_frames",rows);
            result.put("package",info.packageName);
            result.put("isDebuggerConnected",android.os.Debug.isDebuggerConnected());
            result.put("waitingForDebugger",android.os.Debug.waitingForDebugger());
            result.put("mikromServiceNativeResult",probeService("mikrom"));
            result.put("mikromServiceResultMeaning","-1=pending JNI lookup/call exception; 0=null; 1=non-null");
            result.put("libsotweakDlopenFlags0",probeDlopen("libsotweak.so",0));
            result.put("libmthookDlopenFlags0",probeDlopen("libmthook.so",0));
            result.put("libpineDlopenFlags0",probeDlopen("libpine.so",0));
            result.put("libaocDlopenFlags0",probeDlopen("libaoc.so",0));
            result.put("scope","Actual Android AppComponentFactory native JNI call stack in separate research package. Own captureStack native method; original N.al not executed or represented as a captured frame.");
            File files=new File(info.dataDir,"files");files.mkdirs();
            try(FileOutputStream out=new FileOutputStream(new File(files,"factory-stack.json"))) {
                out.write(result.toString(2).getBytes("UTF-8"));
            }
        }catch(Throwable error){android.util.Log.e("StackProbe","capture failed",error);}
        return super.instantiateClassLoader(loader,info);
    }
}
