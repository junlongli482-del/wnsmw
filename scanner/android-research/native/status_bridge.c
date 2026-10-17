#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

/* Exported C++ ABI, invoked without replacing original preprocessing/inference.
 * cv::Mat uses an external BGR buffer; oversized aligned storage is opaque. */
extern void mat_from_data(void *,int,int,int,void *,unsigned) __asm__("_ZN2cv3MatC1EiiiPvj");
extern void mat_destroy(void *) __asm__("_ZN2cv3MatD1Ev");
extern void mat_empty(void *) __asm__("_ZN2cv3MatC1Ev");
extern void mat_copy(void *,const void *) __asm__("_ZN2cv3MatC1ERKS0_");
extern void transform_cut(void *,const void *,const void *,double *,int,int,int)
    __asm__("_ZN8pagescan12transformCutENSt6__ndk16vectorIN2cv6Point_IiEENS0_9allocatorIS4_EEEENS2_3MatEPdbbi");
extern int dewarp_process(void *,const void *,void *,int,int);
extern char *string_allocate(void *,unsigned) __asm__("_ZN2cv6String8allocateEj");
extern void string_release(void *) __asm__("_ZN2cv6String10deallocateEv");
extern void original_imread(void *,const void *,int) __asm__("_ZN2cv6imreadERKNS_6StringEi");
extern void *InitDewarpContext(int);
extern void *InitDewarpContext_old(int);
extern void ReleaseDewarpContext(void *);
extern void ReleaseDewarpContext_old(void *);
extern float get_warp_mat(void *,const void *,void *);
extern int radar_init(void) __asm__("_ZN6scanet16init_model_radarEv");
extern void radar_run(const void *,float *,int *,int) __asm__("_ZN6scanet14document_radarERKN2cv3MatERfRii");
extern void radar_release(int) __asm__("_ZN6scanet19release_model_radarEi");
extern int scan_init(int) __asm__("_ZN6scanet10init_modelEi");
extern void scan_release(int) __asm__("_ZN6scanet13release_modelEi");
extern void original_scan(const void *,void *,int,int,int) __asm__("_ZN6scanet4scanERKN2cv3MatERS1_ibb");
extern void original_sharp(const void *,void *,int) __asm__("_ZN6scanet12sharpEnhanceERKN2cv3MatERS1_i");

JNIEXPORT jintArray JNICALL
Java_org_localresearch_scanner_OriginalStatus_enhanceStages(JNIEnv *env,jclass type,jintArray pixels,jint width,jint height) {
    (void)type;
    if(!pixels || width<1 || height<1 || width>8192 || height>8192 ||
       (*env)->GetArrayLength(env,pixels)!=width*height)return 0;
    unsigned char *bgr=malloc((size_t)width*height*3);if(!bgr)return 0;
    jint *data=(*env)->GetIntArrayElements(env,pixels,0);if(!data){free(bgr);return 0;}
    for(int i=0;i<width*height;i++){bgr[i*3]=(unsigned char)data[i];bgr[i*3+1]=(unsigned char)(data[i]>>8);bgr[i*3+2]=(unsigned char)(data[i]>>16);}
    (*env)->ReleaseIntArrayElements(env,pixels,data,JNI_ABORT);
    unsigned char *sharp_data=malloc((size_t)width*height*3);
    if(!sharp_data){free(bgr);return 0;}
    uint64_t source[32]={0},dest[32]={0},sharp[32]={0};mat_from_data(source,height,width,16,bgr,(unsigned)width*3);mat_empty(dest);
    /* Original sharpEnhance writes param_2.data directly without create(). */
    mat_from_data(sharp,height,width,16,sharp_data,(unsigned)width*3);
    int session=scan_init(2);jintArray result=0;
    if(session>=0) {
        original_scan(source,dest,session,0,1);original_sharp(dest,sharp,2);
        uint32_t *a=(uint32_t *)dest,*b=(uint32_t *)sharp;
        if(a[2]==(unsigned)height && a[3]==(unsigned)width && b[2]==(unsigned)height && b[3]==(unsigned)width && a[4] && b[4]) {
            result=(*env)->NewIntArray(env,width*height*2);jint *row=malloc((size_t)width*4);
            if(!row){result=0;}else {
                for(int k=0;k<2;k++)for(int y=0;y<height;y++) {
                    uint32_t *header=k?b:a;const unsigned char *line=(const unsigned char *)((uintptr_t)header[4]+(size_t)y*header[12]);
                    for(int x=0;x<width;x++)row[x]=(jint)(0xff000000u|((unsigned)line[x*3+2]<<16)|((unsigned)line[x*3+1]<<8)|line[x*3]);
                    if(result)(*env)->SetIntArrayRegion(env,result,k*width*height+y*width,width,row);
                }
                free(row);
            }
        }
        scan_release(session);
    }
    mat_destroy(sharp);mat_destroy(dest);mat_destroy(source);free(sharp_data);free(bgr);return result;
}

/* Same native transformCut -> dewarp_process stages as CropDewarpImagePos.
 * Intermediate image is retained; original branches and returns unmodified. */
JNIEXPORT jintArray JNICALL
Java_org_localresearch_scanner_OriginalStatus_geometry(JNIEnv *env,jclass type,jintArray pixels,
        jint width,jint height,jintArray corners,jboolean old,jstring path) {
    (void)type;
    if(!pixels || !corners || width<1 || height<1 || width>8192 || height>8192 ||
       (*env)->GetArrayLength(env,pixels)!=width*height || (*env)->GetArrayLength(env,corners)!=8)return 0;
    unsigned char *bgr=malloc((size_t)width*height*3);if(!bgr)return 0;
    jint *data=(*env)->GetIntArrayElements(env,pixels,0);if(!data){free(bgr);return 0;}
    for(int i=0;i<width*height;i++){bgr[i*3]=(unsigned char)data[i];bgr[i*3+1]=(unsigned char)(data[i]>>8);bgr[i*3+2]=(unsigned char)(data[i]>>16);}
    (*env)->ReleaseIntArrayElements(env,pixels,data,JNI_ABORT);
    int points[8];(*env)->GetIntArrayRegion(env,corners,0,8,points);
    void *vector[3]={points,points+8,points+8};double geometry[9]={0};
    uint64_t source[32]={0},copy[32]={0},crop[32]={0},field[32]={0},dest[32]={0};
    if(path) {
        const char *name=(*env)->GetStringUTFChars(env,path,0);
        if(!name){free(bgr);return 0;}
        uint32_t text[2]={0};size_t length=strlen(name);char *storage=string_allocate(text,(unsigned)length);
        memcpy(storage,name,length);(*env)->ReleaseStringUTFChars(env,path,name);
        original_imread(source,text,1);string_release(text);
    }else mat_from_data(source,height,width,16,bgr,(unsigned)width*3);
    mat_copy(copy,source);
    transform_cut(crop,vector,copy,geometry,0,0,0);mat_destroy(copy);
    void *context=old?InitDewarpContext_old(2):InitDewarpContext(2);
    mat_empty(field);mat_empty(dest);
    float confidence=context?get_warp_mat(context,crop,field):-1;
    mat_copy(copy,crop);int status=context?dewarp_process(context,copy,dest,1,2):-10000;mat_destroy(copy);
    uint32_t *a=(uint32_t *)crop,*b=(uint32_t *)dest;
    int ah=a[2],aw=a[3],bh=b[2],bw=b[3];jintArray result=0;
    if(aw>0 && ah>0 && bw>0 && bh>0 && aw<=8192 && ah<=8192 && bw<=8192 && bh<=8192 &&
       a[4] && b[4] && (a[0]&0xfff)==16 && (b[0]&0xfff)==16) {
        result=(*env)->NewIntArray(env,6+aw*ah+bw*bh);
        union {float f;int i;} bits;bits.f=confidence;
        jint info[6]={status,aw,ah,bw,bh,bits.i};if(result)(*env)->SetIntArrayRegion(env,result,0,6,info);
        jint *row=malloc((size_t)(aw>bw?aw:bw)*4);
        if(!row){result=0;}else {
            int offset=6;
            for(int k=0;k<2;k++) {
                uint32_t *header=k?b:a;int w=header[3],h=header[2];
                for(int y=0;y<h;y++) {
                    const unsigned char *line=(const unsigned char *)((uintptr_t)header[4]+(size_t)y*header[12]);
                    for(int x=0;x<w;x++)row[x]=(jint)(0xff000000u|((unsigned)line[x*3+2]<<16)|((unsigned)line[x*3+1]<<8)|line[x*3]);
                    if(result)(*env)->SetIntArrayRegion(env,result,offset,w,row);offset+=w;
                }
            }
            free(row);
        }
    }
    mat_destroy(dest);mat_destroy(field);mat_destroy(crop);mat_destroy(source);free(bgr);
    if(context){if(old)ReleaseDewarpContext_old(context);else ReleaseDewarpContext(context);}
    return result;
}

JNIEXPORT jfloatArray JNICALL
Java_org_localresearch_scanner_OriginalStatus_warp(JNIEnv *env,jclass type,jintArray pixels,jint width,jint height,jboolean old) {
    (void)type;
    if(!pixels || width<1 || height<1 || width>8192 || height>8192 ||
       (*env)->GetArrayLength(env,pixels)!=width*height)return 0;
    unsigned char *bgr=malloc((size_t)width*height*3);
    if(!bgr)return 0;
    jint *data=(*env)->GetIntArrayElements(env,pixels,0);
    if(!data){free(bgr);return 0;}
    for(int i=0;i<width*height;i++) {
        bgr[i*3]=(unsigned char)data[i];bgr[i*3+1]=(unsigned char)(data[i]>>8);bgr[i*3+2]=(unsigned char)(data[i]>>16);
    }
    (*env)->ReleaseIntArrayElements(env,pixels,data,JNI_ABORT);
    uint64_t mat[32]={0},field[32]={0};
    mat_from_data(mat,height,width,16,bgr,(unsigned)width*3);mat_empty(field);
    void *context=old?InitDewarpContext_old(2):InitDewarpContext(2);
    float confidence=context?get_warp_mat(context,mat,field):-1;
    uint32_t *header=(uint32_t *)field;int h=header[2],w=header[3];
    jfloatArray result=0;
    if(h>0 && h<=1024 && w>0 && w<=1024 && header[4] && (header[0]&0xfff)==13) {
        result=(*env)->NewFloatArray(env,7+h*w*2);
        double sum[2]={0,0},squares[2]={0,0};float low=INFINITY,high=-INFINITY;
        for(int y=0;y<h;y++) {
            const float *row=(const float *)((uintptr_t)header[4]+(size_t)y*header[12]);
            if(result)(*env)->SetFloatArrayRegion(env,result,7+y*w*2,w*2,row);
            for(int x=0;x<w*2;x++){double v=row[x];int c=x&1;sum[c]+=v;squares[c]+=v*v;if(v<low)low=v;if(v>high)high=v;}
        }
        double n=(double)h*w;
        jfloat stats[7]={confidence,(float)h,(float)w,low,high,
            (float)sqrt(fmax(0,squares[0]/n-(sum[0]/n)*(sum[0]/n))),
            (float)sqrt(fmax(0,squares[1]/n-(sum[1]/n)*(sum[1]/n)))};
        if(result)(*env)->SetFloatArrayRegion(env,result,0,7,stats);
    }
    mat_destroy(field);mat_destroy(mat);free(bgr);
    if(context){if(old)ReleaseDewarpContext_old(context);else ReleaseDewarpContext(context);}
    return result;
}

JNIEXPORT jfloatArray JNICALL
Java_org_localresearch_scanner_OriginalStatus_radar(JNIEnv *env,jclass type,jintArray pixels,jint width,jint height) {
    (void)type;
    if(!pixels || width<1 || height<1 || width>8192 || height>8192 ||
       (*env)->GetArrayLength(env,pixels)!=width*height)return 0;
    unsigned char *bgr=malloc((size_t)width*height*3);
    if(!bgr)return 0;
    jint *data=(*env)->GetIntArrayElements(env,pixels,0);
    if(!data){free(bgr);return 0;}
    for(int i=0;i<width*height;i++) {
        bgr[i*3]=(unsigned char)data[i];bgr[i*3+1]=(unsigned char)(data[i]>>8);bgr[i*3+2]=(unsigned char)(data[i]>>16);
    }
    (*env)->ReleaseIntArrayElements(env,pixels,data,JNI_ABORT);
    uint64_t mat[32]={0};
    mat_from_data(mat,height,width,16,bgr,(unsigned)width*3);
    int session=radar_init(),category=-1;float score=0;
    if(session>=0){radar_run(mat,&score,&category,session);radar_release(session);}
    mat_destroy(mat);free(bgr);
    jfloat values[3]={(float)category,score,(float)session};
    jfloatArray result=(*env)->NewFloatArray(env,3);
    if(result)(*env)->SetFloatArrayRegion(env,result,0,3,values);
    return result;
}

/* Recovered exported C ABI. Original documentCrop epilogue at ELF 0x772ca
 * moves r10 into r0, proving an integer return despite old decompiler void.
 * Argument order is also exercised by original DetectFrameBorder JNI. */
extern void *InitDocCropContext(int configuration);
extern int documentCrop(void *context,const unsigned char *data,int width,int height,
                        int *quad,int margin,int stride,int pixel_format,int still_image);

JNIEXPORT jlong JNICALL
Java_org_localresearch_scanner_OriginalStatus_createContext(JNIEnv *env,jclass type,jint config) {
    (void)env;(void)type;
    return (jlong)(uintptr_t)InitDocCropContext(config);
}

JNIEXPORT jint JNICALL
Java_org_localresearch_scanner_OriginalStatus_detect(JNIEnv *env,jclass type,jlong handle,
        jbyteArray frame,jint width,jint height,jintArray output) {
    (void)type;
    if(!handle || !frame || !output || width<2 || height<2 || width>1280 || height>1280 ||
       (width&1) || (height&1) || (*env)->GetArrayLength(env,frame)!=width*height*3/2 ||
       (*env)->GetArrayLength(env,output)<8) {
        jclass error=(*env)->FindClass(env,"java/lang/IllegalArgumentException");
        if(error)(*env)->ThrowNew(env,error,"Invalid original detector context or NV21 dimensions");
        return -10000;
    }
    jbyte *data=(*env)->GetByteArrayElements(env,frame,0);
    if(!data)return -10001;
    int quad[8]={-999,-999,-999,-999,-999,-999,-999,-999};
    int status=documentCrop((void *)(uintptr_t)handle,(const unsigned char *)data,width,height,
                           quad,0,0,0,0);
    (*env)->ReleaseByteArrayElements(env,frame,data,JNI_ABORT);
    if(status>=0)(*env)->SetIntArrayRegion(env,output,0,8,(const jint *)quad);
    return status;
}
