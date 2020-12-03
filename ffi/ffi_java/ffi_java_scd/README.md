# 选择性披露方案

## 接口调用Java文件



```java
package com.webank.wedpr.scd;

import com.webank.wedpr.common.CompatibleResult;
import com.webank.wedpr.common.NativeUtils;
import com.webank.wedpr.common.Utils;
import com.webank.wedpr.common.WedprException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

public class NativeInterface {

    // COMPONENT VERSION STRING
    public static String WEDPR_SELECTIVE_DISCLOSURE_LIB_PATH;
    public static String LIBSSL_1_1 = "libssl.so.1.1";
    public static String LIBSSL_1_0 = "libssl.so.10";

    static {
        try {
            String osName = System.getProperty("os.name").toLowerCase();
            if (osName.contains("windows")) {
                WEDPR_SELECTIVE_DISCLOSURE_LIB_PATH =
                        "/WeDPR_dynamic_lib/ffi_scd.dll";
                NativeUtils.loadLibraryFromJar("/WeDPR_dynamic_lib/libeay32md.dll");
                NativeUtils.loadLibraryFromJar("/WeDPR_dynamic_lib/ssleay32md.dll");
            } else if (osName.contains("linux")) {
                if (hasLibsslVersion(LIBSSL_1_0)) {
                    WEDPR_SELECTIVE_DISCLOSURE_LIB_PATH =
                            "/WeDPR_dynamic_lib/libffi_scd_libssl_1_0.so";
                } else if (hasLibsslVersion(LIBSSL_1_1)) {
                    WEDPR_SELECTIVE_DISCLOSURE_LIB_PATH =
                            "/WeDPR_dynamic_lib/libffi_scd_libssl_1_1.so";
                } else {
                    throw new WedprException(
                            "The Linux needs " + LIBSSL_1_1 + " or " + LIBSSL_1_0 + ".");
                }

            } else if (osName.contains("mac")) {
                WEDPR_SELECTIVE_DISCLOSURE_LIB_PATH =
                        "/WeDPR_dynamic_lib/libffi_scd.dylib";
            } else {
                throw new WedprException("Unsupported the os " + osName + ".");
            }
            NativeUtils.loadLibraryFromJar(WEDPR_SELECTIVE_DISCLOSURE_LIB_PATH);

            CompatibleResult compatibleResult = getCompatibleResult();
            Utils.checkVersionCompatible("Selective disclosure", compatibleResult);
        } catch (IOException | WedprException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean hasLibsslVersion(String libsslVersion)
            throws IOException, UnsupportedEncodingException {
        Process process = Runtime.getRuntime().exec("locate " + libsslVersion);
        InputStream inputStream = process.getInputStream();
        BufferedReader bufferedReader =
                new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
        String version = bufferedReader.readLine();
        return version != null;
    }

    private static CompatibleResult getCompatibleResult() {
        String wedprCoreVersion = getVersion();
        CompatibleResult compatibleResult = isCompatible(VERSION);
        compatibleResult.wedprCoreVersion = wedprCoreVersion;
        compatibleResult.sdkVersion = VERSION;
        return compatibleResult;
    }
    /**
     * Gets WeDPR Core version.
     *
     * @return
     */
    public static native String getVersion();

    public static native CompatibleResult isCompatible(String targetVersion);

    public static native IssuerResult issuerMakeCertificateTemplate(String attributeTemplate);

    public static native IssuerResult issuerSignCredential(
            String credentialTemplate,
            String templateSecretey,
            String credentialRequest,
            String userId,
            String nonce);

    public static native UserResult userMakeCredential(
            String credentialInfoInput, String credentialTemplate);

    public static native UserResult userBlindCertificateSignature(
            String credentialSignature,
            String credentialInfo,
            String credentialTemplate,
            String masterSecret,
            String credentialSecretsBlindingFactors,
            String nonceCredential);

    public static native UserResult userProveAttributeDict(
            String verificationPredicateRule,
            String credentialSignature,
            String credentialInfo,
            String credentialTemplate,
            String masterSecret);

    public static native VerifierResult verifierVerifyProof(
            String verificationPredicateRule, String verificationRequest);

    public static native VerifierResult verifierGetRevealedAttrsFromVerifyRequest(
            String verificationRequest);
}

```

## 返回值

```java
package com.webank.wedpr.scd;

import com.webank.wedpr.common.WedprResult;

public class IssuerResult extends WedprResult {
    public String credentialTemplate;
    public String templateSecretKey;
    public String credentialSignature;
    public String issuerNonce;
}
```

```java
package com.webank.wedpr.scd;

import com.webank.wedpr.common.WedprResult;

public class UserResult extends WedprResult {
    public String credentialSignatureRequest;
    public String masterSecret;
    public String credentialSecretsBlindingFactors;
    public String userNonce;
    public String credentialSignature;
    public String verificationRequest;
}
```

```java
package com.webank.wedpr.scd;

import com.webank.wedpr.common.WedprResult;

public class VerifierResult extends WedprResult {
    public String revealedAttributeInfo;
    public String verificationNonce;
    public boolean result;
}
```