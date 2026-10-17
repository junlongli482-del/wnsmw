#include <jni.h>
#include <dlfcn.h>
JNIEXPORT jstring JNICALL Java_org_localresearch_stackprobe_ProbeFactory_probeDlopen(JNIEnv *env,jclass type,jstring name,jint flags) {
    const char *text=(*env)->GetStringUTFChars(env,name,NULL);
    if(!text)return NULL;
    dlerror();void *handle=dlopen(text,flags);const char *error=dlerror();
    jstring result=(*env)->NewStringUTF(env,handle?"NON_NULL":(error?error:"NULL without dlerror"));
    if(handle)dlclose(handle);
    (*env)->ReleaseStringUTFChars(env,name,text);return result;
}
JNIEXPORT jint JNICALL Java_org_localresearch_stackprobe_ProbeFactory_probeService(JNIEnv *env,jclass type,jstring name) {
    jclass manager=(*env)->FindClass(env,"android/os/ServiceManager");
    if(!manager){(*env)->ExceptionClear(env);return -1;}
    jmethodID get=(*env)->GetStaticMethodID(env,manager,"getService","(Ljava/lang/String;)Landroid/os/IBinder;");
    if(!get){(*env)->ExceptionClear(env);return -1;}
    jobject binder=(*env)->CallStaticObjectMethod(env,manager,get,name);
    if((*env)->ExceptionCheck(env)){(*env)->ExceptionClear(env);return -1;}
    return binder?1:0;
}
JNIEXPORT jobjectArray JNICALL Java_org_localresearch_stackprobe_ProbeFactory_captureStack(JNIEnv *env,jclass type) {
    jclass thread=(*env)->FindClass(env,"java/lang/Thread");
    if(!thread)return NULL;
    jmethodID current=(*env)->GetStaticMethodID(env,thread,"currentThread","()Ljava/lang/Thread;");
    jmethodID stack=(*env)->GetMethodID(env,thread,"getStackTrace","()[Ljava/lang/StackTraceElement;");
    if(!current||!stack)return NULL;
    jobject self=(*env)->CallStaticObjectMethod(env,thread,current);
    if((*env)->ExceptionCheck(env)||!self)return NULL;
    return (jobjectArray)(*env)->CallObjectMethod(env,self,stack);
}
