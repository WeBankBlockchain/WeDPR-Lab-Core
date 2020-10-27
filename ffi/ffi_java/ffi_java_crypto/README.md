# how to cross compile with openssl

for android, my ndk version is 23

zshrc

```bash
# for android, you need download openssl in local path
export LDFLAGS="-L~/Downloads/openssl.1.0.2k_for_android_ios/android/openssl-arm64-v8a/lib"
export CPPFLAGS="-I~/Downloads/openssl.1.0.2k_for_android_ios/android/openssl-arm64-v8a/include"
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig"
export PKG_CONFIG_ALLOW_CROSS=1
export OPENSSL_STATIC=1
```

toolchain

```bash

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

explain

```bash
rustup target add armv7-linux-androideabi   # for arm
rustup target add i686-linux-android        # for x86
rustup target add aarch64-linux-android     # for arm64
rustup target add x86_64-linux-android      # for x86_64
rustup target add x86_64-unknown-linux-gnu  # for linux-x86-64
rustup target add x86_64-apple-darwin       # for darwin (macOS)
rustup target add x86_64-pc-windows-gnu     # for win32-x86-64-gnu
rustup target add x86_64-pc-windows-msvc    # for win32-x86-64-msvc
```

rust link args

```bash
# some old android version need this option
export RUSTFLAGS="-C link-arg=-Wl,--hash-style=both"
```

```bash
cargo ndk --target i686-linux-android --android-platform 21 -- build --release
# aarch64-linux-android
# armv7-linux-androideabi
# i686-linux-android
# target 21 is android 5.0, work fine in old oppo, 26 is too high run in old version
```

```bash
export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/21.3.6528147

/Users/asher/Library/Android/sdk/ndk/21.3.6528147cd
```

```bash
```

```java
public class NativeInterface {
    public static native CryptoResult secp256k1EciesEncrypt(String pubKey, String plaintext);
    
    public static native CryptoResult secp256k1EciesDecrypt(String priKey, String ciphertext);
    
    public static native CryptoResult secp256k1GenKeyPair();
    
    public static native CryptoResult keccak256Hash(String message);
    
    public static native CryptoResult secp256k1Sign(String priKey, String messageHash);
    
    public static native CryptoResult secp256k1Verify(String pubKey, String message, String signature);
}
```

```java
package com.webank.wedpr.crypto;
import com.webank.wedpr.common.WedprException;
import com.webank.wedpr.common.WedprResult;

public class CryptoResult extends WedprResult {
    public String signature;
    public String publicKey;
    public String privateKey;
    public String hash;
    public boolean booleanResult;
    public String encryptedData;
    public String decryptedData;
}
```

```java
package com.webank.wedpr.common;

/** Base result class used by WeDPR Java SDK. */
public class WedprResult {
  public String wedprErrorMessage;

  /** Checks whether any error occurred. */
  public boolean hasError() {
    return wedprErrorMessage != null;
  }
}
```