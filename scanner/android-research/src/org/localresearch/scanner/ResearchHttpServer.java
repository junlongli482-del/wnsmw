package org.localresearch.scanner;

import android.graphics.Bitmap;
import org.json.JSONArray;
import org.json.JSONObject;
import java.net.*;
import java.io.*;
import java.util.*;

/** Loopback-only research transport; PC gateway uses adb forward. */
final class ResearchHttpServer {
    private static ResearchHttpServer instance;
    private final android.content.Context app;
    private final ServerSocket listener;
    static synchronized void start(android.content.Context context) throws Exception {
        if(instance==null)instance=new ResearchHttpServer(context.getApplicationContext());
    }
    private ResearchHttpServer(android.content.Context context) throws Exception {
        app=context;listener=new ServerSocket(18765,8,InetAddress.getByName("127.0.0.1"));
        new Thread(()->{while(!listener.isClosed())try(Socket socket=listener.accept()) {socket.setSoTimeout(30000);serve(socket);}
            catch(Throwable error){android.util.Log.e("REA_HTTP","request failed",error);}},"original-jni-http").start();
    }
    private static String line(InputStream input) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();int value;
        while((value=input.read())!=-1) {if(value==10)break;if(value!=13)out.write(value);if(out.size()>8192)throw new IOException("Header too large");}
        if(value==-1 && out.size()==0)throw new EOFException();return out.toString("US-ASCII");
    }
    private static void respond(Socket socket,int code,String type,byte[] data) throws IOException {
        OutputStream output=socket.getOutputStream();String header="HTTP/1.1 "+code+" "+(code==200?"OK":"Error")+"\r\nContent-Type: "+type+"\r\nContent-Length: "+data.length+"\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
        output.write(header.getBytes("US-ASCII"));output.write(data);output.flush();
    }
    private void serve(Socket socket) throws Exception {
        try {
            InputStream input=new BufferedInputStream(socket.getInputStream());String[] request=line(input).split(" ");
            if(request.length!=3)throw new IllegalArgumentException("Invalid request");
            Map<String,String> headers=new HashMap<>();
            for(int i=0;i<64;i++){String row=line(input);if(row.isEmpty())break;int colon=row.indexOf(':');if(colon<1)throw new IllegalArgumentException("Invalid header");headers.put(row.substring(0,colon).toLowerCase(Locale.ROOT),row.substring(colon+1).trim());}
            String route=request[1];
            if(route.equals("/health") && request[0].equals("GET")) {
                NativeScannerEngine.get();respond(socket,200,"application/json","{\"status\":\"ready\",\"engine\":\"original-apk-jni\",\"scope\":\"research\"}".getBytes("UTF-8"));return;
            }
            if(!request[0].equals("POST")){respond(socket,404,"text/plain",new byte[0]);return;}
            int length=Integer.parseInt(headers.getOrDefault("content-length","-1"));
            if(length<1 || length>32*1024*1024)throw new IllegalArgumentException("Invalid content length");
            byte[] body=new byte[length];int count=0;
            while(count<length){int got=input.read(body,count,length-count);if(got<0)throw new EOFException();count+=got;}
            NativeScannerEngine engine=NativeScannerEngine.get();long started=android.os.SystemClock.elapsedRealtimeNanos();
            if(route.equals("/detect") || route.equals("/detect-rgba") || route.equals("/detect-curve") || route.equals("/detect-curve-rgba")) {
                int width=Integer.parseInt(headers.getOrDefault("x-frame-width","0")),height=Integer.parseInt(headers.getOrDefault("x-frame-height","0"));
                if(width<2 || height<2 || width>1280 || height>1280 || (width&1)!=0 || (height&1)!=0)throw new IllegalArgumentException("Even frame dimensions 2..1280 required");
                if(route.endsWith("-rgba")) {
                    if(length!=width*height*4)throw new IllegalArgumentException("RGBA length mismatch");
                    int[] pixels=new int[width*height];for(int i=0;i<pixels.length;i++)pixels[i]=0xff000000|((body[4*i]&255)<<16)|((body[4*i+1]&255)<<8)|(body[4*i+2]&255);
                    Bitmap bitmap=Bitmap.createBitmap(pixels,width,height,Bitmap.Config.ARGB_8888);body=NativeScannerEngine.nv21(bitmap);bitmap.recycle();
                }else if(length!=width*height*3/2)throw new IllegalArgumentException("NV21 length mismatch");
                if(route.startsWith("/detect-curve")) {
                    NativeScannerEngine.CurveDetection detection=engine.detectCurve(body,width,height);
                    JSONObject result=new JSONObject();JSONArray quad=new JSONArray(),curve=new JSONArray(),raw=new JSONArray();
                    for(int v:detection.quad)raw.put(v);
                    boolean valid=detection.code>=0 && NativeScannerEngine.valid(detection.quad,width,height);
                    if(valid){for(int v:detection.quad)quad.put(v);for(int v:detection.curve)curve.put(v);}
                    result.put("quad",quad);result.put("curve",curve);result.put("raw_quad",raw);result.put("native_status",detection.code);
                    result.put("width",width);result.put("height",height);result.put("stable",detection.code==1 && valid);
                    result.put("native_ms",(android.os.SystemClock.elapsedRealtimeNanos()-started)/1e6);
                    respond(socket,200,"application/json",result.toString().getBytes("UTF-8"));return;
                }
                NativeScannerEngine.Detection detection=engine.detectDetailed(body,width,height);
                int[] quad=detection.quad;JSONObject result=new JSONObject();JSONArray values=new JSONArray();
                if(quad!=null)for(int v:quad)values.put(v);result.put("quad",values);result.put("width",width);result.put("height",height);
                JSONArray raw=new JSONArray();for(int value:detection.rawQuad)raw.put(value);
                result.put("native_status",detection.code);result.put("raw_quad",raw);result.put("stable",detection.code==1 && quad!=null);
                result.put("native_ms",(android.os.SystemClock.elapsedRealtimeNanos()-started)/1e6);
                respond(socket,200,"application/json",result.toString().getBytes("UTF-8"));return;
            }
            if(route.equals("/scan")) {
                String stem="request-"+System.nanoTime();File folder=new File(app.getCacheDir(),stem);if(!folder.mkdir())throw new IOException("Cannot create request directory");
                try {
                    File file=engine.processJpeg(body,folder,stem);ByteArrayOutputStream output=new ByteArrayOutputStream();
                    try(InputStream source=new FileInputStream(file)){byte[] buffer=new byte[8192];int n;while((n=source.read(buffer))!=-1)output.write(buffer,0,n);}
                    respond(socket,200,"image/png",output.toByteArray());
                }finally{File[] files=folder.listFiles();if(files!=null)for(File f:files)f.delete();folder.delete();}
                return;
            }
            respond(socket,404,"text/plain",new byte[0]);
        }catch(Throwable error) {
            android.util.Log.e("REA_HTTP","request failed",error);JSONObject result=new JSONObject();result.put("error",error.getMessage());
            respond(socket,error instanceof IllegalArgumentException?400:422,"application/json",result.toString().getBytes("UTF-8"));
        }
    }
}
