package org.localresearch.scanner;

import android.Manifest;
import android.app.Activity;
import android.os.Bundle;
import android.content.pm.PackageManager;
import android.graphics.*;
import android.hardware.Camera;
import android.view.*;
import android.widget.*;
import java.io.File;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

/** Camera proof-of-concept for the recovered original JNI, not the protected app UI. */
@SuppressWarnings("deprecation")
public final class CameraActivity extends Activity implements SurfaceHolder.Callback {
    private SurfaceView preview;private FrameLayout viewport;private Outline overlay;private TextView status;private Button shutter;
    private Camera camera;private int width,height,orientation;private boolean resumed,surfaceReady,shooting;
    private volatile NativeScannerEngine engine;private volatile int frameCount;
    private final AtomicBoolean busy=new AtomicBoolean();
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setBackgroundColor(Color.BLACK);
        status=new TextView(this);status.setTextColor(Color.WHITE);status.setText("正在初始化扫描模块…");root.addView(status);
        viewport=new FrameLayout(this);preview=new SurfaceView(this);viewport.addView(preview);
        overlay=new Outline();viewport.addView(overlay,new FrameLayout.LayoutParams(-1,-1));root.addView(viewport,new LinearLayout.LayoutParams(-1,0,1));
        shutter=new Button(this);shutter.setText("拍照并处理");shutter.setEnabled(false);root.addView(shutter);setContentView(root);
        preview.getHolder().addCallback(this);viewport.addOnLayoutChangeListener((v,l,t,r,b,ol,ot,orr,ob)->fitPreview());
        shutter.setOnClickListener(v->capture());
        worker.execute(()->{try {engine=NativeScannerEngine.get();runOnUiThread(()->{status.setText("请将整张试卷放入画面");openCamera();});}
            catch(Throwable error){showError(error);}});
    }
    @Override protected void onResume(){super.onResume();resumed=true;if(checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.CAMERA},7);else openCamera();}
    @Override protected void onPause(){resumed=false;closeCamera();super.onPause();}
    @Override protected void onDestroy(){worker.shutdown();super.onDestroy();}
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] results){super.onRequestPermissionsResult(request,permissions,results);if(request==7 && results.length>0 && results[0]==PackageManager.PERMISSION_GRANTED)openCamera();else status.setText("需要相机权限才能拍摄试卷");}
    public void surfaceCreated(SurfaceHolder holder){surfaceReady=true;openCamera();}
    public void surfaceChanged(SurfaceHolder holder,int format,int w,int h){fitPreview();}
    public void surfaceDestroyed(SurfaceHolder holder){surfaceReady=false;closeCamera();}
    private void openCamera() {
        if(!resumed || !surfaceReady || engine==null || camera!=null || checkSelfPermission(Manifest.permission.CAMERA)!=PackageManager.PERMISSION_GRANTED)return;
        try {
            int id=0;Camera.CameraInfo info=new Camera.CameraInfo();
            for(int i=0;i<Camera.getNumberOfCameras();i++){Camera.getCameraInfo(i,info);if(info.facing==Camera.CameraInfo.CAMERA_FACING_BACK){id=i;break;}}
            Camera.getCameraInfo(id,info);camera=Camera.open(id);Camera.Parameters parameters=camera.getParameters();
            Camera.Size chosen=null;long best=Long.MAX_VALUE;
            for(Camera.Size size:parameters.getSupportedPreviewSizes()){
                long score=(long)(Math.abs(size.width/(double)size.height-4.0/3)*1000000)+Math.abs(size.width*size.height-640*480);
                if(score<best){best=score;chosen=size;}
            }
            width=chosen.width;height=chosen.height;parameters.setPreviewSize(width,height);parameters.setPreviewFormat(ImageFormat.NV21);
            Camera.Size picture=null;long area=0;
            for(Camera.Size size:parameters.getSupportedPictureSizes())if(size.width*(long)size.height>area){picture=size;area=size.width*(long)size.height;}
            if(picture!=null)parameters.setPictureSize(picture.width,picture.height);
            if(parameters.getSupportedFocusModes()!=null && parameters.getSupportedFocusModes().contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE))parameters.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
            int rotation=getWindowManager().getDefaultDisplay().getRotation()*90;
            orientation=(info.orientation-rotation+360)%360;parameters.setRotation(orientation);
            camera.setParameters(parameters);camera.setDisplayOrientation(orientation);camera.setPreviewDisplay(preview.getHolder());
            for(int i=0;i<3;i++)camera.addCallbackBuffer(new byte[width*height*3/2]);
            camera.setPreviewCallbackWithBuffer((data,source)->{
                if(!shooting && busy.compareAndSet(false,true)) {
                    byte[] copy=data.clone();int fw=width,fh=height;
                    worker.execute(()->{try {long started=android.os.SystemClock.elapsedRealtimeNanos();NativeScannerEngine.Detection detection=engine.detectDetailed(copy,fw,fh);int[] quad=detection.quad;double ms=(android.os.SystemClock.elapsedRealtimeNanos()-started)/1e6;int count=++frameCount;
        runOnUiThread(()->{overlay.quad=overlay.display.update(quad);overlay.stable=detection.code==1;overlay.invalidate();if(!shooting)status.setText((quad==null?"寻找纸张":detection.code==1?"已识别纸张":"请保持稳定")+" · "+String.format(java.util.Locale.ROOT,"%.0f ms",ms));});
                        android.util.Log.i("REA_CAMERA","frame="+count+" status="+detection.code+" quad="+java.util.Arrays.toString(quad)+" raw="+java.util.Arrays.toString(detection.rawQuad)+" ms="+ms);
                    }catch(Throwable error){showError(error);}finally{busy.set(false);}});
                }
                source.addCallbackBuffer(data);
            });
            camera.startPreview();fitPreview();shutter.setEnabled(true);
        }catch(Throwable error){closeCamera();showError(error);}
    }
    private void fitPreview(){if(width==0 || viewport.getWidth()==0)return;float ratio=(orientation%180==0?width/(float)height:height/(float)width);
        int w=viewport.getWidth(),h=(int)(w/ratio);if(h>viewport.getHeight()){h=viewport.getHeight();w=(int)(h*ratio);}
        FrameLayout.LayoutParams layout=new FrameLayout.LayoutParams(w,h,Gravity.CENTER);preview.setLayoutParams(layout);overlay.invalidate();}
    private void closeCamera(){shutter.setEnabled(false);overlay.display.reset();overlay.quad=null;overlay.invalidate();if(camera!=null){camera.setPreviewCallbackWithBuffer(null);camera.stopPreview();camera.release();camera=null;}}
    private void capture(){if(camera==null || shooting)return;shooting=true;shutter.setEnabled(false);status.setText("正在拍摄…");
        try {camera.takePicture(null,null,(jpeg,source)->{status.setText("正在处理试卷…");worker.execute(()->{
            try {File output=engine.processJpeg(jpeg,getFilesDir(),"capture-"+System.currentTimeMillis());
                android.util.Log.i("REA_CAMERA","processed="+output.getAbsolutePath());runOnUiThread(()->showResult(output));
            }catch(Throwable error){runOnUiThread(()->{showError(error);restartPreview();});}
        });});}catch(Throwable error){showError(error);restartPreview();}}
    private void restartPreview(){shooting=false;if(camera!=null && resumed)try{camera.startPreview();shutter.setEnabled(true);}catch(RuntimeException error){showError(error);}}
    private void showResult(File file){
        ImageView image=new ImageView(this);image.setAdjustViewBounds(true);image.setImageBitmap(BitmapFactory.decodeFile(file.getAbsolutePath()));
        new android.app.AlertDialog.Builder(this).setTitle("扫描结果").setView(image).setPositiveButton("继续拍下一页",(dialog,which)->restartPreview()).setOnCancelListener(dialog->restartPreview()).show();
        status.setText("已保存第 "+getFilesDir().list((dir,name)->name.endsWith("-scan.png")).length+" 页");
    }
    private void showError(Throwable error){android.util.Log.e("REA_CAMERA","camera probe failed",error);runOnUiThread(()->status.setText("处理失败："+error.getMessage()));}
    private final class Outline extends View {
        final RecoveredBorderDisplay display=new RecoveredBorderDisplay(getResources().getDisplayMetrics().density);
        int[] quad;boolean stable;final Paint paint=new Paint(Paint.ANTI_ALIAS_FLAG);
        Outline(){super(CameraActivity.this);setWillNotDraw(false);paint.setColor(0xff4de1a0);paint.setStyle(Paint.Style.STROKE);paint.setStrokeWidth(4);}
        @Override protected void onDraw(Canvas canvas){super.onDraw(canvas);if(quad==null || width==0)return;Path path=new Path();
            for(int i=0;i<4;i++){float x=quad[i*2]/(float)width,y=quad[i*2+1]/(float)height,rx=x,ry=y;
                if(orientation==90){rx=1-y;ry=x;}else if(orientation==180){rx=1-x;ry=1-y;}else if(orientation==270){rx=y;ry=1-x;}
                float px=preview.getLeft()+rx*preview.getWidth(),py=preview.getTop()+ry*preview.getHeight();if(i==0)path.moveTo(px,py);else path.lineTo(px,py);}
            paint.setColor(stable?0xff4de1a0:0xffffce68);path.close();canvas.drawPath(path,paint);
        }
    }
}
