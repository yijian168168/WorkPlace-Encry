package com.encry.sign.test;

import com.encry.sign.RsaSignUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.symmetric.ARC4;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * @author ZhangQingrong
 * @date 2018/1/24 13:42
 */
public class RsaSignUtilTest {

    @Test
    public void testRsaSignUtil(){
        try {
            String tobeSigned = "123456789123456789123456789123456789123456789123456789";

            byte[] bytes = FileUtils.readFileToByteArray(new File("E:\\test.ks"));
            String privateKey = Base64.encodeBase64String(bytes);
            String privateKeyPassword = "123456";
            String sign = RsaSignUtil.sign(tobeSigned, privateKey, privateKeyPassword);
            System.out.println("sign : ---------------------> " + sign);
            String urlEncodeSign = URLEncoder.encode(sign, "UTF-8");
            System.out.println("urlEncodeSign : ------------> " + urlEncodeSign);

            byte[] publicKeyBytes = FileUtils.readFileToByteArray(new File("E:\\test.cer"));
            String publicKey = Base64.encodeBase64String(publicKeyBytes);
            String urlDecodeSign = URLDecoder.decode(urlEncodeSign,"UTF-8");
            System.out.println("urlDecodeSign : ------------> " + urlDecodeSign);
            boolean verify = RsaSignUtil.verify(publicKey, urlDecodeSign, tobeSigned);
            System.out.println("verify : -------------------> " + verify);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
