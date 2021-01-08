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