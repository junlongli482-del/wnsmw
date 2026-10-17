package org.localresearch.scanner;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import com.intsig.nativelib.PageScanner;
import com.intsig.nativelib.MagicEnhancer;
import java.io.File;
import java.io.FileOutputStream;

/** Serialized research adapter. All detection, crop/dewarp and enhancement use APK JNI. */
final class NativeScannerEngine {
    private static NativeScannerEngine instance;
    final int detectContext,dewarpContext,enhanceContext;
    final long statusContext;
    private int contourContext=-1;
    static final class CurveDetection {
        final int code;final int[] quad,curve;
        CurveDetection(int status,int[] corners,int[] points){code=status;quad=corners;curve=points;}
    }
    synchronized CurveDetection detectCurve(byte[] data,int width,int height) {
        if(contourContext<0) {
            contourContext=PageScanner.initContourMask(2);
            if(contourContext<1)throw new IllegalStateException("Original contour initialization failed");
            PageScanner.InitDetectCurveBorder(3);
        }
        int[] quad=new int[8],curve=new int[160];
        int result=PageScanner.DetectCurveBorderYUV(data,width,height,quad,6,new int[48],20,curve,1,contourContext);
        return new CurveDetection(result,quad,curve);
    }
    static synchronized NativeScannerEngine get() {
        if(instance==null)instance=new NativeScannerEngine();
        return instance;
    }
    private NativeScannerEngine() {
        PageScanner.load();MagicEnhancer.load();
        detectContext=PageScanner.initDetectBorder(2);
        dewarpContext=PageScanner.initCropDewarp(2);
        enhanceContext=MagicEnhancer.initDeshadowModelNew(2);
        statusContext=OriginalStatus.createContext(2);
        if(detectContext<1 || dewarpContext<1 || enhanceContext<0 || statusContext==0)throw new IllegalStateException("Original model initialization failed");
        // Original AutoDrawBorderHandle uses 11 outside sandbox mode.
        PageScanner.InitDetectFrameBorder(11);
    }
    synchronized int[] detect(byte[] data,int width,int height) {
        return detectDetailed(data,width,height).quad;
    }
    static final class Detection {
        final int code;final int[] quad,rawQuad;
        Detection(int status,int[] raw,int width,int height) {
            code=status;rawQuad=raw;
            quad=(status==1 || status==3) && valid(raw,width,height)?raw:null;
        }
    }
    synchronized Detection detectDetailed(byte[] data,int width,int height) {
        int[] quad={-999,-999,-999,-999,-999,-999,-999,-999};
        int code=OriginalStatus.detect(statusContext,data,width,height,quad);
        return new Detection(code,quad,width,height);
    }
    static boolean valid(int[] quad,int width,int height) {
        if(quad==null || quad.length!=8)return false;
        long twiceArea=0;
        for(int i=0;i<4;i++) {
            int j=(i+1)%4,x=quad[i*2],y=quad[i*2+1];
            if(x<0 || y<0 || x>width || y>height)return false;
            twiceArea+=(long)x*quad[j*2+1]-(long)y*quad[j*2];
        }
        return Math.abs(twiceArea)>width*(long)height/50;
    }
    synchronized File processJpeg(byte[] jpeg,File directory,String stem) throws Exception {
        File input=new File(directory,stem+"-source.jpg");
        try(FileOutputStream out=new FileOutputStream(input)){out.write(jpeg);}
        android.media.ExifInterface exif=new android.media.ExifInterface(input.getAbsolutePath());
        int orientation=exif.getAttributeInt(android.media.ExifInterface.TAG_ORIENTATION,android.media.ExifInterface.ORIENTATION_NORMAL);
        if(orientation>=2 && orientation<=8) {
            // BitmapFactory uses raw pixel coordinates, but original cv::imread
            // honors EXIF. Keep the native crop in that same raw coordinate space.
            // ExifInterface rewrites metadata without recompressing JPEG pixels.
            exif.setAttribute(android.media.ExifInterface.TAG_ORIENTATION,"1");
            exif.saveAttributes();
        }
        Bitmap source=BitmapFactory.decodeByteArray(jpeg,0,jpeg.length);
        if(source==null)throw new IllegalArgumentException("Cannot decode JPEG");
        int width=source.getWidth(),height=source.getHeight(),smallWidth=480;
        int smallHeight=Math.max(2,((int)Math.round(height*480.0/width)+1)&~1);
        Bitmap small=Bitmap.createScaledBitmap(source,smallWidth,smallHeight,true);
        byte[] nv21=nv21(small);if(small!=source)small.recycle();source.recycle();
        int[] quad={-999,-999,-999,-999,-999,-999,-999,-999};
        PageScanner.DetectBorderYUV(nv21,smallWidth,smallHeight,quad,detectContext,0);
        if(!valid(quad,smallWidth,smallHeight))throw new IllegalStateException("未识别到完整纸张，请重新拍摄");
        for(int i=0;i<8;i++)quad[i]=(int)Math.round(quad[i]*(i%2==0?width/(double)smallWidth:height/(double)smallHeight));
        File crop=new File(directory,stem+"-crop.png");
        int cropResult=PageScanner.CropDewarpImagePosFile(input.getAbsolutePath(),quad,crop.getAbsolutePath(),dewarpContext,false);
        if(cropResult<0)throw new IllegalStateException("Original crop failed: "+cropResult);
        Bitmap decoded=BitmapFactory.decodeFile(crop.getAbsolutePath());
        if(decoded==null)throw new IllegalStateException("Original crop did not produce an image");
        Bitmap bitmap=decoded.copy(Bitmap.Config.ARGB_8888,true);decoded.recycle();
        PageScanner.InitDetectFrameBorder(11);
        int enhanceResult=MagicEnhancer.deshadowBitmapNew(bitmap,3,enhanceContext);
        if(enhanceResult<0){bitmap.recycle();throw new IllegalStateException("Original enhancement failed: "+enhanceResult);}
        android.graphics.Matrix matrix=new android.graphics.Matrix();
        switch(orientation) {
            case 2:matrix.setScale(-1,1);break;
            case 3:matrix.setRotate(180);break;
            case 4:matrix.setScale(1,-1);break;
            case 5:matrix.setRotate(90);matrix.postScale(-1,1);break;
            case 6:matrix.setRotate(90);break;
            case 7:matrix.setRotate(270);matrix.postScale(-1,1);break;
            case 8:matrix.setRotate(270);break;
        }
        if(!matrix.isIdentity()) {Bitmap rotated=Bitmap.createBitmap(bitmap,0,0,bitmap.getWidth(),bitmap.getHeight(),matrix,true);if(rotated!=bitmap)bitmap.recycle();bitmap=rotated;}
        File output=new File(directory,stem+"-scan.png");
        try(FileOutputStream out=new FileOutputStream(output)){if(!bitmap.compress(Bitmap.CompressFormat.PNG,100,out))throw new IllegalStateException("PNG write failed");}
        bitmap.recycle();return output;
    }
    /** Android bitmap-to-camera NV21 adapter; this contains no paper/image enhancement algorithm. */
    static byte[] nv21(Bitmap bitmap) {
        int width=bitmap.getWidth(),height=bitmap.getHeight();int[] pixels=new int[width*height];
        bitmap.getPixels(pixels,0,width,0,0,width,height);byte[] bytes=new byte[width*height*3/2];
        int uv=width*height;
        for(int y=0;y<height;y++)for(int x=0;x<width;x++) {
            int c=pixels[y*width+x],r=(c>>16)&255,g=(c>>8)&255,b=c&255;
            bytes[y*width+x]=(byte)clamp(((66*r+129*g+25*b+128)>>8)+16);
            if((y&1)==0 && (x&1)==0) {
                bytes[uv++]=(byte)clamp(((112*r-94*g-18*b+128)>>8)+128);
                bytes[uv++]=(byte)clamp(((-38*r-74*g+112*b+128)>>8)+128);
            }
        }
        return bytes;
    }
    private static int clamp(int value){return Math.max(0,Math.min(255,value));}
}
