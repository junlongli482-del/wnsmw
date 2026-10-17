package com.intsig.nativelib;

/** JNI descriptors verified against SHA-1-matched restored PageScanner DEX. */
public final class PageScanner {
    public static void load() {
        System.loadLibrary("MNN");
        System.loadLibrary("opencv");
        System.loadLibrary("pagescanner");
    }
    public static native int initDetectBorder(int threads);
    public static native int initContourMask(int threads);
    public static native int InitDetectFrameBorder(int frameCapacity);
    public static native int InitDetectCurveBorder(int frameCapacity);
    public static native int DetectCurveBorderYUV(byte[] nv21,int width,int height,int[] corners,int numSamples,int[] samples,int numConnect,int[] curve,int fixType,int context);
    public static native int DetectFrameBorder(byte[] nv21,int width,int height,int[] corners,int context,int margin);
    public static native int DetectBorderYUV(byte[] nv21,int width,int height,int[] corners,int context,int margin);
    public static native int initCropDewarp(int threads);
    public static native int initCropDewarpOld(int threads);
    public static native int DewarpImgBitmapNew(android.graphics.Bitmap bitmap,int context);
    public static native int CropDewarpImagePosFile(String input,int[] corners,String output,int context,boolean option);
    public static native int CurveCropDewarpImagePos2(android.graphics.Bitmap bitmap,int[] corners,int dewarpContext,int contourContext,boolean option);
}
