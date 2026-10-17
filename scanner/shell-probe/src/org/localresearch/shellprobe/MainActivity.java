package org.localresearch.shellprobe;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.*;

public class MainActivity extends Activity {
    private synchronized void record(String value) {
        Log.i("ShellProbe",value);
        try(FileOutputStream out=openFileOutput("probe.txt",MODE_APPEND)) {
            out.write((value+"\n").getBytes("UTF-8"));
        } catch(Exception e) { Log.e("ShellProbe","record",e); }
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view=new TextView(this);
        view.setText("Original x86 shell JNI research. Separate package/context; no scanner UI.");
        setContentView(view);
        Runnable probe=() -> {
            record("package="+getPackageName()+" nativeLibraryDir="+getApplicationInfo().nativeLibraryDir);
            record("pid="+android.os.Process.myPid()+" Build.HARDWARE="+android.os.Build.HARDWARE);
            for(String name:new String[]{"libexec.so","libexecmain.so"}) {
                record("load_enter="+name);
                try { System.load(getApplicationInfo().nativeLibraryDir+"/"+name); record("load_return="+name); }
                catch(Throwable error) { record("load_throw="+name+" "+Log.getStackTraceString(error)); }
            }
            if(getIntent().getBooleanExtra("call_al",false)) {
                record("al_enter scope=separate-package-loader-with-original-installed-metadata");
                try {
                    android.content.pm.ApplicationInfo info=getPackageManager().getApplicationInfo("com.intsig.camscanner",0);
                    record("al_metadata sourceDir="+info.sourceDir+" dataDir="+info.dataDir);
                    org.json.JSONArray stack=new org.json.JSONArray();
                    for(StackTraceElement frame:Thread.currentThread().getStackTrace()) {
                        org.json.JSONObject row=new org.json.JSONObject();
                        row.put("className",frame.getClassName());row.put("methodName",frame.getMethodName());
                        row.put("fileName",frame.getFileName());row.put("lineNumber",frame.getLineNumber());
                        stack.put(row);
                    }
                    record("al_stack="+stack.toString());
                    ClassLoader result=s.h.e.l.l.N.al(getClassLoader(),info,
                        "com.intsig.camscanner","com.intsig.camscanner.launch.CsApplication");
                    record("al_return="+String.valueOf(result));
                } catch(Throwable error) { record("al_throw="+Log.getStackTraceString(error)); }
            }
            record("probe_end");
        };
        if(getIntent().getBooleanExtra("probe_main_thread",false))probe.run();
        else new Thread(probe,"shell-research-load").start();
    }
}
