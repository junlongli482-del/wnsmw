package org.localresearch.scanner;

import android.app.Activity;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import android.widget.TextView;
import com.intsig.nativelib.PageScanner;
import com.intsig.nativelib.MagicEnhancer;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public final class MainActivity extends Activity {
    private TextView status;
    private byte[] asset(String name) throws Exception {
        try(InputStream input=getAssets().open(name);ByteArrayOutputStream out=new ByteArrayOutputStream()) {
            byte[] buffer=new byte[8192];int count;
            while((count=input.read(buffer))!=-1)out.write(buffer,0,count);
            return out.toByteArray();
        }
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);status=new TextView(this);status.setText("Running original native libraries on fixture frames…");setContentView(status);
        if(getIntent().getStringExtra("stage")==null) {
            android.widget.LinearLayout menu=new android.widget.LinearLayout(this);menu.setOrientation(android.widget.LinearLayout.VERTICAL);
            menu.setPadding(24,24,24,24);
            TextView title=new TextView(this);title.setText("试卷扫描 · 原库研究验证");title.setTextSize(24);menu.addView(title);
            android.widget.Button camera=new android.widget.Button(this);camera.setText("打开相机扫描");menu.addView(camera);
            camera.setOnClickListener(v->startActivity(new android.content.Intent(this,CameraActivity.class)));
            android.widget.Button gallery=new android.widget.Button(this);gallery.setText("查看已处理示例");menu.addView(gallery);gallery.setOnClickListener(v->showSamples());
            for(String[] entry:new String[][]{{"原库完整处理示例","android-adapter"},{"动态框连续帧验证","frames"}}) {
                android.widget.Button button=new android.widget.Button(this);button.setText(entry[0]);menu.addView(button);
                button.setOnClickListener(v->startActivity(new android.content.Intent(this,MainActivity.class).putExtra("stage",entry[1])));
            }
            setContentView(menu);return;
        }
        new Thread(() -> runProbe(),"native-research").start();
    }
    private void runProbe() {
        JSONObject report=new JSONObject();JSONArray samples=new JSONArray();
        try {
            report.put("scope","Research harness, original APK libraries; no protected app UI. Android x86 ARM translation is not physical-phone timing.");
            report.put("pid",android.os.Process.myPid());
            report.put("device",android.os.Build.FINGERPRINT);
            report.put("supported_abis",new JSONArray(java.util.Arrays.asList(android.os.Build.SUPPORTED_ABIS)));
            long start=SystemClock.elapsedRealtimeNanos();PageScanner.load();
            report.put("library_load_ms",(SystemClock.elapsedRealtimeNanos()-start)/1e6);Log.i("REA_NATIVE","libraries loaded");
            String stage=getIntent().getStringExtra("stage");
            if(stage!=null && !stage.equals("frames")) { runBitmapProbe(stage,report);return; }
            start=SystemClock.elapsedRealtimeNanos();int context=PageScanner.initDetectBorder(2);
            report.put("context",context);report.put("model_init_ms",(SystemClock.elapsedRealtimeNanos()-start)/1e6);Log.i("REA_NATIVE","context="+context);
            if(context<1 || context>10)throw new IllegalStateException("Invalid original context ID "+context);
            for(String name:new String[]{"photo-1","photo-2"}) {
                PageScanner.InitDetectFrameBorder(7);byte[] frame=asset(name+".nv21");
                if(frame.length!=480*360*3/2)throw new IllegalStateException("Invalid fixture length");
                JSONObject sample=new JSONObject();JSONArray frames=new JSONArray();sample.put("source",name);
                for(int i=0;i<9;i++) {
                    int[] corners={-999,-999,-999,-999,-999,-999,-999,-999};
                    start=SystemClock.elapsedRealtimeNanos();PageScanner.DetectFrameBorder(frame,480,360,corners,context,0);
                    double ms=(SystemClock.elapsedRealtimeNanos()-start)/1e6;
                    JSONObject result=new JSONObject();result.put("frame",i);result.put("milliseconds",ms);
                    JSONArray quad=new JSONArray();for(int value:corners)quad.put(value);result.put("quad",quad);frames.put(result);
                    Log.i("REA_NATIVE",name+" frame="+i+" ms="+ms+" quad="+quad.toString());
                }
                sample.put("frames",frames);samples.put(sample);
            }
            report.put("status","executed");
        } catch(Throwable error) {
            try { report.put("status","failed");report.put("error",Log.getStackTraceString(error)); } catch(Exception ignored) {}
            if(getIntent().getStringExtra("stage")!=null)try { saveReport(report,"bitmap-report.json"); } catch(Exception ignored) {}
            Log.e("REA_NATIVE","probe failed",error);
        }
        try {
            report.put("samples",samples);
            try(FileOutputStream output=new FileOutputStream(new File(getFilesDir(),"native-report.json"))) {
                output.write(report.toString(2).getBytes("UTF-8"));
            }
            String text=report.toString(2);runOnUiThread(() -> status.setText(text));Log.i("REA_NATIVE","report saved");
        } catch(Exception error) { Log.e("REA_NATIVE","report write failed",error); }
    }

    private void saveReport(JSONObject report,String name) throws Exception {
        try(FileOutputStream output=new FileOutputStream(new File(getFilesDir(),name))) {
            output.write(report.toString(2).getBytes("UTF-8"));
        }
        Log.i("REA_NATIVE",name+" saved "+report.optString("status"));
    }
    private void runBitmapProbe(String stage,JSONObject report) throws Exception {
        if(stage.equals("recovered-enhance-branches")) {
            MagicEnhancer.load();report.put("stage",stage);JSONArray outputs=new JSONArray();report.put("outputs",outputs);
            report.put("scope","Same retained crop, original old/new enhancement branches, mode3. Old init=(1,fast,false), fast=false/true covers local and batch-sharpen switch; new threads=1. Controlled branch comparison, actual installed original-app configuration unknown.");
            for(int branch=0;branch<3;branch++) {
                boolean newer=branch==2,fast=branch==1;
                int session=newer?MagicEnhancer.initDeshadowModelNew(1):MagicEnhancer.initDeshadowModel2(1,fast,false);
                if(session<0)throw new IllegalStateException("Enhance init failed "+session);
                try {
                    for(String stem:new String[]{"photo-1","photo-2"}) {
                        byte[] bytes=asset(stem+"-crop.png");Bitmap decoded=BitmapFactory.decodeByteArray(bytes,0,bytes.length);
                        Bitmap bitmap=decoded.copy(Bitmap.Config.ARGB_8888,true);decoded.recycle();
                        long start=SystemClock.elapsedRealtimeNanos();
                        int result=newer?MagicEnhancer.deshadowBitmapNew(bitmap,3,session):MagicEnhancer.deshadowBitmap2(bitmap,3,session);
                        if(result<0)throw new IllegalStateException("Enhance failed "+result);
                        String name=stem+"-recovered-enhance-"+(newer?"new":fast?"old-fast":"old")+".png";
                        try(FileOutputStream stream=new FileOutputStream(new File(getFilesDir(),name))){bitmap.compress(Bitmap.CompressFormat.PNG,100,stream);}
                        JSONObject row=new JSONObject();row.put("file",name);row.put("branch",newer?"new":fast?"old-fast":"old");
                        row.put("native_status",result);row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-start)/1e6);outputs.put(row);bitmap.recycle();
                        report.put("status","processing "+name);saveReport(report,"bitmap-report.json");
                    }
                } finally {if(newer)MagicEnhancer.releaseDeshadowModelNew(session);else MagicEnhancer.releaseDeshadowModel2(session);}
            }
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("curve-crop")) {
            report.put("stage",stage);JSONArray outputs=new JSONArray();report.put("outputs",outputs);
            int detect=PageScanner.initDetectBorder(2),contour=PageScanner.initContourMask(2),dewarp=PageScanner.initCropDewarp(2);
            report.put("scope","Original CurveCropDewarpImagePos2(bitmap,quad,dewarp,contour,true), restored cut_optimization=2 branch. Research-selected branch and threads=2; no original app configuration or output equivalence claim.");
            for(String stem:new String[]{"photo-1","photo-2"}) {
                byte[] jpeg=asset(stem+".jpg");Bitmap decoded=BitmapFactory.decodeByteArray(jpeg,0,jpeg.length);
                Bitmap bitmap=decoded.copy(Bitmap.Config.ARGB_8888,true);decoded.recycle();
                int[] quad=new int[8];int detection=PageScanner.DetectBorderYUV(asset(stem+".nv21"),480,360,quad,detect,0);
                if(!NativeScannerEngine.valid(quad,480,360))throw new IllegalStateException("No valid quad");
                for(int i=0;i<8;i++)quad[i]=(int)Math.round(quad[i]*(i%2==0?bitmap.getWidth()/480.0:bitmap.getHeight()/360.0));
                long start=SystemClock.elapsedRealtimeNanos();int result=PageScanner.CurveCropDewarpImagePos2(bitmap,quad,dewarp,contour,true);
                if(result<0)throw new IllegalStateException("Curve crop failed "+result);
                String name=stem+"-android-curve-crop.png";
                try(FileOutputStream stream=new FileOutputStream(new File(getFilesDir(),name))){bitmap.compress(Bitmap.CompressFormat.PNG,100,stream);}
                JSONObject row=new JSONObject();row.put("file",name);row.put("native_status",result);row.put("detection_status",detection);
                row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-start)/1e6);row.put("width",bitmap.getWidth());row.put("height",bitmap.getHeight());
                JSONArray q=new JSONArray();for(int v:quad)q.put(v);row.put("quad",q);outputs.put(row);bitmap.recycle();
            }
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("curve-border")) {
            report.put("stage",stage);JSONArray records=new JSONArray();report.put("records",records);
            report.put("scope","Original JNI curve detector and initContourMask from restored SessionIdPoolManager; restored local defaults: frames=3,samples=6,connect=20,fix=1. Research-selected threads=2 and 480x360 fixtures; not original UI or physical camera acceptance.");
            int context=PageScanner.initContourMask(2);report.put("context",context);
            if(context<1)throw new IllegalStateException("Invalid detector context "+context);
            for(String stem:new String[]{"photo-1","photo-2"}) {
                int init=PageScanner.InitDetectCurveBorder(3);
                JSONObject sample=new JSONObject();sample.put("source",stem);sample.put("init_status",init);
                JSONArray frames=new JSONArray();sample.put("frames",frames);records.put(sample);
                byte[] original=asset(stem+".nv21"),blank=new byte[original.length];
                java.util.Arrays.fill(blank,0,480*360,(byte)80);
                java.util.Arrays.fill(blank,480*360,blank.length,(byte)128);
                for(int index=0;index<21;index++) {
                    boolean empty=index>=9 && index<12;
                    int[] quad=new int[8],points=new int[6*8],curve=new int[20*8];
                    long started=SystemClock.elapsedRealtimeNanos();
                    int result=PageScanner.DetectCurveBorderYUV(empty?blank:original,480,360,quad,6,points,20,curve,1,context);
                    JSONObject row=new JSONObject();row.put("frame",index);row.put("fixture",empty?"blank":"page");
                    row.put("native_status",result);row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-started)/1e6);
                    JSONArray q=new JSONArray(),p=new JSONArray(),c=new JSONArray();
                    for(int v:quad)q.put(v);for(int v:points)p.put(v);for(int v:curve)c.put(v);
                    row.put("quad",q);row.put("samples",p);row.put("curve",c);frames.put(row);
                    report.put("status","processing "+stem+" frame "+index);saveReport(report,"bitmap-report.json");
                }
            }
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("enhance-stages")) {
            MagicEnhancer.load();report.put("stage",stage);JSONArray outputs=new JSONArray();report.put("outputs",outputs);
            for(String stem:new String[]{"photo-1","photo-2"}) {
                byte[] png=asset(stem+"-crop.png");Bitmap image=BitmapFactory.decodeByteArray(png,0,png.length);
                int w=image.getWidth(),h=image.getHeight();int[] pixels=new int[w*h];image.getPixels(pixels,0,w,0,0,w,h);image.recycle();
                long start=SystemClock.elapsedRealtimeNanos();int[] result=OriginalStatus.enhanceStages(pixels,w,h);
                if(result==null)throw new IllegalStateException("Original enhancement stages failed");
                for(int k=0;k<2;k++) {
                    image=Bitmap.createBitmap(result,k*w*h,w,w,h,Bitmap.Config.ARGB_8888);
                    String name=stem+"-android-enhance-stage-"+(k==0?"scan":"sharp")+".png";
                    try(FileOutputStream stream=new FileOutputStream(new File(getFilesDir(),name))){image.compress(Bitmap.CompressFormat.PNG,100,stream);}image.recycle();
                    JSONObject row=new JSONObject();row.put("file",name);row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-start)/1e6);outputs.put(row);
                }
            }
            report.put("scope","Original scan(config2,params0/1), then sharpEnhance(strength2) on same asset crop as Bitmap mode3 fixture. Branch selected for direct stage observation; no model/tensor replacements, not original protected UI.");
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("geometry-stages") || stage.equals("geometry-file-stages")) {
            report.put("stage",stage);JSONArray records=new JSONArray(),outputs=new JSONArray();report.put("records",records);report.put("outputs",outputs);
            int detectContext=PageScanner.initDetectBorder(2);
            for(String stem:new String[]{"photo-1","photo-2"}) {
                byte[] jpeg=asset(stem+".jpg");Bitmap bitmap=BitmapFactory.decodeByteArray(jpeg,0,jpeg.length);
                File input=new File(getFilesDir(),stem+"-geometry-source.jpg");
                try(FileOutputStream stream=new FileOutputStream(input)){stream.write(jpeg);}
                int w=bitmap.getWidth(),h=bitmap.getHeight();int[] pixels=new int[w*h];bitmap.getPixels(pixels,0,w,0,0,w,h);bitmap.recycle();
                int[] quad={-999,-999,-999,-999,-999,-999,-999,-999};PageScanner.DetectBorderYUV(asset(stem+".nv21"),480,360,quad,detectContext,0);
                for(int i=0;i<8;i++)quad[i]=(int)Math.round(quad[i]*(i%2==0?w/480.0:h/360.0));
                for(boolean old:new boolean[]{false,true}) {
                    long start=SystemClock.elapsedRealtimeNanos();int[] result=OriginalStatus.geometry(pixels,w,h,quad,old,stage.equals("geometry-file-stages")?input.getAbsolutePath():null);
                    if(result==null)throw new IllegalStateException("Original geometry stages failed");
                    JSONObject row=new JSONObject();row.put("sample",stem);row.put("model",old?"alternate":"default");row.put("status_code",result[0]);row.put("confidence",Float.intBitsToFloat(result[5]));
                    row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-start)/1e6);records.put(row);int offset=6;
                    for(int k=0;k<2;k++) {
                        int width=result[1+k*2],height=result[2+k*2];
                        Bitmap image=Bitmap.createBitmap(result,offset,width,width,height,Bitmap.Config.ARGB_8888);offset+=width*height;
                        String name=stem+"-android-"+(stage.equals("geometry-file-stages")?"geometry-file":"geometry")+"-"+(old?"alternate":"default")+(k==0?"-perspective":"-dewarp")+".png";
                        try(FileOutputStream stream=new FileOutputStream(new File(getFilesDir(),name))){image.compress(Bitmap.CompressFormat.PNG,100,stream);}image.recycle();
                        JSONObject file=new JSONObject();file.put("file",name);outputs.put(file);
                    }
                }
            }
            report.put("scope","Controlled stage observation: original transformCut then original get_warp_mat and original dewarp_process(bool1,mode2); no branch replacement. geometry-file-stages uses original cv::imread JPEG, geometry-stages uses Bitmap/BGR transport. Intermediate perspective and final PNG retained, not a remap hook/count or protected UI observation. Model contexts released between default and alternate; no persistent default dewarp context.");
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("warp-confidence")) {
            report.put("stage",stage);JSONArray records=new JSONArray();report.put("records",records);
            for(String stem:new String[]{"photo-1","photo-2"}) {
                for(boolean old:new boolean[]{false,true}) {
                    byte[] png=asset(stem+"-crop.png");Bitmap bitmap=BitmapFactory.decodeByteArray(png,0,png.length);
                    int w=bitmap.getWidth(),h=bitmap.getHeight();int[] pixels=new int[w*h];bitmap.getPixels(pixels,0,w,0,0,w,h);bitmap.recycle();
                    long start=SystemClock.elapsedRealtimeNanos();float[] result=OriginalStatus.warp(pixels,w,h,old);
                    if(result==null || result.length<7)throw new IllegalStateException("Original warp probe failed");
                    String name=stem+"-android-warp-field-"+(old?"alternate":"default")+".f32";
                    java.nio.ByteBuffer buffer=java.nio.ByteBuffer.allocate((result.length-7)*4).order(java.nio.ByteOrder.LITTLE_ENDIAN);
                    for(int i=7;i<result.length;i++)buffer.putFloat(result[i]);
                    try(FileOutputStream stream=new FileOutputStream(new File(getFilesDir(),name))){stream.write(buffer.array());}
                    JSONObject row=new JSONObject();row.put("sample",stem);row.put("model",old?"alternate":"default");row.put("field_file",name);
                    row.put("confidence",result[0]);row.put("field_height",(int)result[1]);row.put("field_width",(int)result[2]);row.put("min",result[3]);row.put("max",result[4]);
                    row.put("std0",result[5]);row.put("std1",result[6]);row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-start)/1e6);records.put(row);
                }
            }
            report.put("scope","Original Android InitDewarpContext/default and old + get_warp_mat. Original model initialization, input preprocessing, inference, smoothing and confidence; BGR transport only. Asset crops originate from earlier host geometry for comparison, not camera acceptance.");
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("radar")) {
            report.put("stage",stage);JSONArray records=new JSONArray();report.put("records",records);
            NativeScannerEngine engine=NativeScannerEngine.get();
            for(String stem:new String[]{"photo-1","photo-2"}) {
                byte[] jpeg=asset(stem+".jpg");
                engine.processJpeg(jpeg,getFilesDir(),stem+"-android-radar");
                for(String kind:new String[]{"source","crop"}) {
                    Bitmap bitmap=kind.equals("source")?BitmapFactory.decodeByteArray(jpeg,0,jpeg.length):BitmapFactory.decodeFile(new File(getFilesDir(),stem+"-android-radar-crop.png").getAbsolutePath());
                    int w=bitmap.getWidth(),h=bitmap.getHeight();int[] pixels=new int[w*h];bitmap.getPixels(pixels,0,w,0,0,w,h);bitmap.recycle();
                    long start=SystemClock.elapsedRealtimeNanos();float[] result=OriginalStatus.radar(pixels,w,h);
                    if(result==null || result[0]<0)throw new IllegalStateException("Original radar failed");
                    JSONObject row=new JSONObject();row.put("sample",stem);row.put("input",kind);row.put("width",w);row.put("height",h);
                    row.put("class_index",(int)result[0]);row.put("score",result[1]);row.put("session",(int)result[2]);row.put("ms",(SystemClock.elapsedRealtimeNanos()-start)/1e6);
                    row.put("mode3_branch",result[0]==0 || result[0]==5?"scan":"scan_old");records.put(row);
                }
            }
            report.put("scope","Original exported document_radar, original cv::Mat and preprocessing/MNN; ARGB to BGR transport only. Class labels unknown. Routing applies to researched Bitmap mode3 parameters, not protected UI defaults.");
            report.put("status","executed");saveReport(report,"bitmap-report.json");return;
        }
        if(stage.equals("http-server")) {
            NativeScannerEngine.get();ResearchHttpServer.start(this);report.put("stage",stage);report.put("status","executed");
            report.put("bind","127.0.0.1:18765");saveReport(report,"bitmap-report.json");
            runOnUiThread(()->status.setText("原库接入服务已就绪，等待本机转发请求。"));return;
        }
        if(stage.equals("android-adapter")) {runAndroidAdapter(report);return;}
        if(stage.equals("full-native")) {runFullNative(report);return;}
        JSONArray outputs=new JSONArray();report.put("stage",stage);report.put("outputs",outputs);
        report.put("status","initializing");saveReport(report,"bitmap-report.json");
        long start=SystemClock.elapsedRealtimeNanos();
        boolean enhance=stage.equals("enhance"),chain=stage.equals("pipeline");int context,enhanceContext=-1;
        if(enhance || chain) { MagicEnhancer.load();enhanceContext=MagicEnhancer.initDeshadowModelNew(2); }
        if(enhance)context=enhanceContext;
        else context=stage.equals("dewarp-old")?PageScanner.initCropDewarpOld(2):PageScanner.initCropDewarp(2);
        report.put("context",context);report.put("init_ms",(SystemClock.elapsedRealtimeNanos()-start)/1e6);
        if(chain)report.put("enhance_context",enhanceContext);
        if(context<(enhance?0:1))throw new IllegalStateException("Invalid context "+context);
        int mode=getIntent().getIntExtra("mode",0);report.put("mode",mode);
        for(String stem:new String[]{"photo-1","photo-2"}) {
            byte[] bytes=asset(stem+"-crop.png");
            Bitmap bitmap=BitmapFactory.decodeByteArray(bytes,0,bytes.length).copy(Bitmap.Config.ARGB_8888,true);
            String name=stem+"-android-"+stage+(enhance?"-mode"+mode:"")+".png";
            report.put("status","processing "+name);saveReport(report,"bitmap-report.json");
            start=SystemClock.elapsedRealtimeNanos();
            if(enhance)MagicEnhancer.deshadowBitmapNew(bitmap,mode,context);
            else PageScanner.DewarpImgBitmapNew(bitmap,context);
            if(chain)MagicEnhancer.deshadowBitmapNew(bitmap,3,enhanceContext);
            double ms=(SystemClock.elapsedRealtimeNanos()-start)/1e6;
            try(FileOutputStream output=new FileOutputStream(new File(getFilesDir(),name))) { bitmap.compress(Bitmap.CompressFormat.PNG,100,output); }
            JSONObject result=new JSONObject();result.put("file",name);result.put("milliseconds",ms);
            result.put("width",bitmap.getWidth());result.put("height",bitmap.getHeight());outputs.put(result);bitmap.recycle();
            Log.i("REA_NATIVE",name+" ms="+ms);
        }
        report.put("status","executed");saveReport(report,"bitmap-report.json");
        String text=report.toString(2);runOnUiThread(() -> status.setText(text));
    }
    private void runAndroidAdapter(JSONObject report) throws Exception {
        JSONArray outputs=new JSONArray();report.put("stage","android-adapter");report.put("outputs",outputs);
        report.put("status","initializing");saveReport(report,"bitmap-report.json");
        NativeScannerEngine engine=NativeScannerEngine.get();
        report.put("scope","Same adapter used for Android camera JPEG. Original libraries perform detection, crop/dewarp and enhancement; Android Bitmap decode/resize and Java NV21 conversion supply detection input. No PC image/inference bridge. Research-selected mode/configuration, no original UI equivalence.");
        for(String stem:new String[]{"photo-1","photo-2"}) {
            report.put("status","processing "+stem);saveReport(report,"bitmap-report.json");
            long started=SystemClock.elapsedRealtimeNanos();File output=engine.processJpeg(asset(stem+".jpg"),getFilesDir(),stem+"-android-adapter");
            JSONObject row=new JSONObject();row.put("file",output.getName());row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-started)/1e6);outputs.put(row);
            JSONObject crop=new JSONObject();crop.put("file",stem+"-android-adapter-crop.png");outputs.put(crop);
        }
        report.put("status","executed");saveReport(report,"bitmap-report.json");
        String text=report.toString(2);runOnUiThread(()->{status.setText(text);showSamples();});
    }
    private void showSamples() {
        android.widget.ScrollView scroll=new android.widget.ScrollView(this);
        android.widget.LinearLayout content=new android.widget.LinearLayout(this);content.setOrientation(android.widget.LinearLayout.VERTICAL);scroll.addView(content);
        boolean found=false;
        for(String stem:new String[]{"photo-1","photo-2"}) {
            File image=new File(getFilesDir(),stem+"-android-adapter-scan.png");if(!image.exists())continue;found=true;
            TextView label=new TextView(this);label.setText(stem.equals("photo-1")?"试卷第 1 组":"试卷第 2 组");content.addView(label);
            android.widget.ImageView view=new android.widget.ImageView(this);view.setAdjustViewBounds(true);view.setImageBitmap(BitmapFactory.decodeFile(image.getAbsolutePath()));content.addView(view,new android.widget.LinearLayout.LayoutParams(-1,-2));
        }
        if(!found){TextView empty=new TextView(this);empty.setText("请先点击“原库完整处理示例”生成结果。");content.addView(empty);}
        new android.app.AlertDialog.Builder(this).setTitle("处理结果").setView(scroll).setPositiveButton("关闭",null).show();
    }
    private void runFullNative(JSONObject report) throws Exception {
        JSONArray outputs=new JSONArray();report.put("stage","full-native");report.put("outputs",outputs);
        report.put("status","initializing");saveReport(report,"bitmap-report.json");
        int detect=PageScanner.initDetectBorder(2),dewarp=PageScanner.initCropDewarp(2);
        MagicEnhancer.load();int enhance=MagicEnhancer.initDeshadowModelNew(2);
        report.put("detect_context",detect);report.put("dewarp_context",dewarp);report.put("enhance_context",enhance);
        report.put("scope","Original Android JPEG decode, detection, crop/dewarp and enhancement libraries. Researcher scales 480x360 detection corners to input dimensions and selects mode=3/order; not protected original UI defaults or physical-phone performance.");
        for(String stem:new String[]{"photo-1","photo-2"}) {
            report.put("status","processing "+stem);saveReport(report,"bitmap-report.json");
            long start=SystemClock.elapsedRealtimeNanos();byte[] jpeg=asset(stem+".jpg");
            BitmapFactory.Options info=new BitmapFactory.Options();info.inJustDecodeBounds=true;BitmapFactory.decodeByteArray(jpeg,0,jpeg.length,info);
            File input=new File(getFilesDir(),stem+"-source.jpg");
            try(FileOutputStream stream=new FileOutputStream(input)){stream.write(jpeg);}
            int[] quad={-999,-999,-999,-999,-999,-999,-999,-999};
            PageScanner.DetectBorderYUV(asset(stem+".nv21"),480,360,quad,detect,0);
            for(int i=0;i<8;i++) {if(quad[i]<0)throw new IllegalStateException("Detection missing");quad[i]=(int)Math.round(quad[i]*(i%2==0?info.outWidth/480.0:info.outHeight/360.0));}
            File crop=new File(getFilesDir(),stem+"-android-full-native-crop.png");
            PageScanner.CropDewarpImagePosFile(input.getAbsolutePath(),quad,crop.getAbsolutePath(),dewarp,false);
            Bitmap decoded=BitmapFactory.decodeFile(crop.getAbsolutePath());
            if(decoded==null)throw new IllegalStateException("No native crop output");
            Bitmap bitmap=decoded.copy(Bitmap.Config.ARGB_8888,true);decoded.recycle();
            double cropMs=(SystemClock.elapsedRealtimeNanos()-start)/1e6;
            MagicEnhancer.deshadowBitmapNew(bitmap,3,enhance);
            String name=stem+"-android-full-native.png";
            try(FileOutputStream stream=new FileOutputStream(new File(getFilesDir(),name))){bitmap.compress(Bitmap.CompressFormat.PNG,100,stream);}
            JSONObject row=new JSONObject();row.put("file",name);row.put("width",bitmap.getWidth());row.put("height",bitmap.getHeight());
            row.put("detect_crop_ms",cropMs);row.put("milliseconds",(SystemClock.elapsedRealtimeNanos()-start)/1e6);
            JSONArray q=new JSONArray();for(int value:quad)q.put(value);row.put("input_quad",q);outputs.put(row);
            JSONObject cropRow=new JSONObject();cropRow.put("file",crop.getName());outputs.put(cropRow);bitmap.recycle();
        }
        report.put("status","executed");saveReport(report,"bitmap-report.json");
        String text=report.toString(2);runOnUiThread(() -> status.setText(text));
    }
}
