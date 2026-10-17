package com.intsig.nativelib;

import android.graphics.Bitmap;

/** JNI descriptors verified against SHA-1-matched restored MagicEnhancer DEX. */
public final class MagicEnhancer {
    public static void load() { System.loadLibrary("magicenhancer"); }
    public static native int initDeshadowModelNew(int configFlag);
    public static native int deshadowBitmapNew(Bitmap bitmap,int mode,int session);
    public static native int initDeshadowModel2(int threads,boolean fast,boolean affinity);
    public static native int deshadowBitmap2(Bitmap bitmap,int mode,int session);
    public static native void releaseDeshadowModel2(int session);
    public static native void releaseDeshadowModelNew(int session);
}
