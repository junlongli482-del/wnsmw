package org.localresearch.scanner;

/** Thin JNI transport of original exported documentCrop result; no detector replacement. */
final class OriginalStatus {
    static {System.loadLibrary("research_status");}
    static native long createContext(int config);
    static native int detect(long context,byte[] nv21,int width,int height,int[] quad);
    static native float[] radar(int[] argb,int width,int height);
    static native float[] warp(int[] argb,int width,int height,boolean old);
    static native int[] geometry(int[] argb,int width,int height,int[] quad,boolean old,String originalJpegPath);
    static native int[] enhanceStages(int[] argb,int width,int height);
}
