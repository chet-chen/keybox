import json
import os
import random
import string


def xor(src, key):
    return (hex(src[i] ^ key[i]) for i in range(len(src)))


if __name__ == '__main__':
    with open('config.json', 'r') as f:
        config = json.load(f)
    output = config['output']
    package = config['package']

    # 生成 Keybox.java
    package_path = output + package.replace('.', '/')
    if not os.path.exists(package_path):
        os.makedirs(package_path)
    keyboxJava = open(package_path + '/Keybox.java', 'w')
    keyboxJava.write(f"""package {package};
    
import android.content.Context;

public class Keybox {{

    static {{
        System.loadLibrary("key-box");
    }}

    private static String[] keys;

    public static String[] getKeys(Context context) {{
        if (keys == null) {{
            keys = getKeysJNI(context);
        }}
        return keys;
    }}
    
    private static native String[] getKeysJNI(Context context);
}}""")
    keyboxJava.close()

    # 生成 keybox.c 文件
    signature_sha1 = config['signature_sha1']
    signature_sha1_bs = bytes(signature_sha1, 'utf-8')
    keys = config['keys']
    keys_bs = [bytes(key, 'utf-8') for key in keys]
    maxLen = max(max(len(key) for key in keys_bs), len(signature_sha1_bs))
    seed = string.digits + string.ascii_letters + string.punctuation
    xor_key_bs = bytes(''.join(random.choice(seed) for i in range(maxLen)), 'utf-8')
    keyboxC = open(output + 'keybox.c', 'w')
    keyboxC.write(f"""#include <jni.h>
#include <string.h>

static const char SIGNATURE[{len(signature_sha1_bs)+1}] = {{
        {','.join(xor(signature_sha1_bs,xor_key_bs))}
}};

static const char KEYS[{len(keys_bs)}][{max(len(key) for key in keys_bs)+1}] = {{
        {','.join('{'+','.join(xor(key, xor_key_bs))+'}' for key in keys_bs)}
}};

static const int KEYS_LENGTH[] = {{{','.join(str(len(key)+1) for key in keys_bs)}}};

static const char XOR_KEY[{len(xor_key_bs)+1}] = {{
        {','.join(hex(i) for i in xor_key_bs)}
}};

# define len(x) ((int) (sizeof(x) / sizeof((x)[0])))

static char *xor(const char *data, char *result, int len) {{
    for (int i = 0; i < len; i++) {{
        result[i] = data[i] ^ XOR_KEY[i];
    }}
    result[len - 1] = 0x0;
    return result;
}}

static char *hexEncode(JNIEnv *env, jbyteArray array, char *chs) {{
    if (array != NULL) {{
        jsize len = (*env)->GetArrayLength(env, array);
        if (len > 0) {{
            jboolean b = JNI_FALSE;
            jbyte *data = (*env)->GetByteArrayElements(env, array, &b);
            int index;
            for (index = 0; index < len; index++) {{
                jbyte bc = data[index];
                jbyte h = (jbyte) ((bc >> 4) & 0x0f);
                jbyte l = (jbyte) (bc & 0x0f);
                jchar ch;
                jchar cl;

                if (h > 9) {{
                    ch = (jchar) ('A' + (h - 10));
                }} else {{
                    ch = (jchar) ('0' + h);
                }}

                if (l > 9) {{
                    cl = (jchar) ('A' + (l - 10));
                }} else {{
                    cl = (jchar) ('0' + l);
                }}
                chs[index * 3] = (char) ch;
                chs[index * 3 + 1] = (char) cl;
                chs[index * 3 + 2] = ':';
            }}
            chs[len * 3 - 1] = 0x0;
            (*env)->ReleaseByteArrayElements(env, array, data, JNI_ABORT);
            return chs;
        }}
    }}
    return NULL;
}}

static int check_signature(JNIEnv *env, jobject context) {{
    jclass context_clazz = (*env)->GetObjectClass(env, context);
    jmethodID methodID_getPackageManager = (*env)->GetMethodID(env,
                                                               context_clazz, "getPackageManager",
                                                               "()Landroid/content/pm/PackageManager;");
    jobject packageManager = (*env)->CallObjectMethod(env, context,
                                                      methodID_getPackageManager);
    jclass pm_clazz = (*env)->GetObjectClass(env, packageManager);
    jmethodID methodID_pm = (*env)->GetMethodID(env, pm_clazz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jmethodID methodID_pack = (*env)->GetMethodID(env, context_clazz,
                                                  "getPackageName", "()Ljava/lang/String;");
    jstring application_package = (*env)->CallObjectMethod(env, context,
                                                           methodID_pack);
    jobject packageInfo = (*env)->CallObjectMethod(env, packageManager,
                                                   methodID_pm, application_package, 64);
    jclass packageinfo_clazz = (*env)->GetObjectClass(env, packageInfo);
    jfieldID fieldID_signatures = (*env)->GetFieldID(env, packageinfo_clazz,
                                                     "signatures",
                                                     "[Landroid/content/pm/Signature;");
    jobjectArray signature_arr = (jobjectArray) (*env)->GetObjectField(env,
                                                                       packageInfo,
                                                                       fieldID_signatures);
    jobject signature = (*env)->GetObjectArrayElement(env, signature_arr, 0);
    jclass signature_clazz = (*env)->GetObjectClass(env, signature);
    jmethodID methodID_toByteArray = (*env)->GetMethodID(env, signature_clazz, "toByteArray",
                                                         "()[B");
    jbyteArray signature_byte = (jbyteArray) (*env)->CallObjectMethod(env, signature,
                                                                      methodID_toByteArray);
    jclass message_digest_class = (*env)->FindClass(env, "java/security/MessageDigest");
    jmethodID methodID_getInstance = (*env)->GetStaticMethodID(env, message_digest_class,
                                                               "getInstance",
                                                               "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring sha1_jstring = (*env)->NewStringUTF(env, "SHA1");
    jobject sha1_digest = (*env)->CallStaticObjectMethod(env, message_digest_class,
                                                         methodID_getInstance,
                                                         sha1_jstring);
    jmethodID methodId_digest = (*env)->GetMethodID(env, message_digest_class, "digest", "([B)[B");
    jbyteArray sha1_byte = (jbyteArray) (*env)->CallObjectMethod(env, sha1_digest, methodId_digest,
                                                                 signature_byte);
    jsize len = (*env)->GetArrayLength(env, sha1_byte);
    char chs[len * 3];
    char *signature_sha1 = hexEncode(env, sha1_byte, chs);

    int SIGNATURE_len = len(SIGNATURE);
    char result[SIGNATURE_len];
    xor(SIGNATURE, result, SIGNATURE_len);
    return strcmp((const char *) result, signature_sha1) == 0;
}}

JNIEXPORT jobjectArray JNICALL
Java_{package.replace('.','_')}_Keybox_getKeysJNI(JNIEnv *env, jclass type, jobject context) {{
    if (check_signature(env, context)) {{
        jobjectArray keys = (*env)->NewObjectArray(env, len(KEYS),
                                                   (*env)->FindClass(env, "java/lang/String"),
                                                   (*env)->NewStringUTF(env, NULL));
        for (int i = 0; i < len(KEYS); i++) {{
            int KEY_len = KEYS_LENGTH[i];
            char result[KEY_len];
            xor(KEYS[i], result, KEY_len);
            (*env)->SetObjectArrayElement(env, keys, i,
                                          (*env)->NewStringUTF(env, (const char *) result));
        }}
        return keys;
    }} else {{
        return NULL;
    }}
}};""")
    keyboxC.close()
