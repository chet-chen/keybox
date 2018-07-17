import json
import os
import random
import string


def xor(text, key):
    result = ''
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(key[i]))
    return result


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
    keys = config['keys']
    maxLen = max(len(key) for key in keys)
    seed = string.digits + string.ascii_letters + string.punctuation
    xor_k = ''.join(random.choice(seed) for i in range(maxLen))
    xor_keys = [xor(key, xor_k) for key in keys]
    keyboxC = open(output + 'keybox.c', 'w')
    keyboxC.write(f"""#include <stdio.h>
    
char keys[] = {{{','.join(('"'+k+'"' for k in xor_keys))}}};
    """)
    keyboxC.close()
