# HD钱包

## 接口调用Java文件

```java
package com.webank.wedpr.hdk;

import com.webank.wedpr.common.WedprResult;

public class HdkResult extends WedprResult {
    public String mnemonic;
    public String masterKey;
    public String extendedPrivateKey;
    public String extendedPublicKey;
}
```

```java
public class NativeInterface {
    public static native HdkResult createMnemonicEn(String word_count);
    public static native HdkResult createMasterKeyEn(String password, String mnemonic);
    public static native HdkResult deriveExtendedKey(String master_key, int purpose_type, int asset_type, int account, int change, int address_index);
}
```