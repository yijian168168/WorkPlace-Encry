package com.encry.sign;

import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Enumeration;

/**
 * SHA1withRSA 算法
 * <p>
 * Created by ZhangQingrong on 2017/1/4.
 */
public class RsaSignUtil {

    /**
     * 算法
     */
    public static final String SIGN_ALGORITHM_SHA256 = "sha256WithRSA";
    public static final String SIGN_ALGORITHM_MD5 = "MD5WithRSA";

    /**
     * 编码格式
     * */
    public static final String CHARSET_GBK = "GBK";
    public static final String CHARSET_UTF8 = "UTF-8";


    /**
     * priKey     私钥
     * tobeSigned 待签字符串
     */
    public static String sign(String tobeSigned, String priKeyValue, String passWord) {
        RSAPrivateCrtKey rsaPrivateCrtKey = KeyUtils.getPriKey(priKeyValue, passWord);
        return sign(rsaPrivateCrtKey, tobeSigned, CHARSET_UTF8, SIGN_ALGORITHM_SHA256);
    }

    /**
     * priKey     私钥
     * tobeSigned 待签字符串
     */
    public static String sign(String tobeSigned, String priKeyValue, String passWord, String encoding, String algorithm) {
        RSAPrivateCrtKey rsaPrivateCrtKey = KeyUtils.getPriKey(priKeyValue, passWord);
        return sign(rsaPrivateCrtKey, tobeSigned, encoding, algorithm);
    }

    private static String sign(RSAPrivateCrtKey priKey, String tobeSigned, String encoding, String algorithm) {
        try {
            Signature sign = Signature.getInstance(algorithm);
            sign.initSign(priKey);
            sign.update(tobeSigned.getBytes(encoding));
            byte signed[] = sign.sign();
            return Base64.encodeBase64String(signed);
        } catch (Exception e) {
            throw new RsaEncryException("sign error", e);
        }
    }

    /**
     * 验证签名
     * pubkey      公钥
     * tobeVerfied 已签名字符串
     * plainText   待校验字符串
     * encoding    编码
     *
     * @return true || false
     */
    public static boolean verify(String pubKey, String tobeVerfied, String plainText) {
        X509Certificate x509Certificate = KeyUtils.getPublicKey(pubKey);
        return verify(x509Certificate, tobeVerfied, plainText, CHARSET_UTF8, SIGN_ALGORITHM_SHA256);
    }

    /**
     * 验证签名
     * pubkey      公钥
     * tobeVerfied 已签名字符串
     * plainText   待校验字符串
     * encoding    编码
     *
     * @return true || false
     */
    public static boolean verify(String pubKey, String tobeVerfied, String plainText, String encoding, String algorithm) {
        X509Certificate x509Certificate = KeyUtils.getPublicKey(pubKey);
        return verify(x509Certificate, tobeVerfied, plainText, encoding, algorithm);
    }

    /**
     * 验证签名
     * pubkey      公钥
     * tobeVerfied 已签名字符串
     * plainText   待校验字符串
     * encoding    编码
     *
     * @return true || false
     */
    public static boolean verify(File pubKey, String tobeVerfied, String plainText, String encoding, String algorithm) {
        X509Certificate x509Certificate = KeyUtils.getPublicKey(pubKey);
        return verify(x509Certificate, tobeVerfied, plainText, encoding, algorithm);
    }


    private static boolean verify(X509Certificate pubkey, String tobeVerfied, String plainText, String encoding, String algorithm) {
        try {
            Signature verify = Signature.getInstance(algorithm);
            verify.initVerify(pubkey);
            verify.update(plainText.getBytes(encoding));
            return verify.verify(Base64.decodeBase64(tobeVerfied));
        } catch (Exception e) {
            throw new RsaEncryException("verify error", e);
        }
    }


    /**
     * 获取密钥
     * <p>
     * Created by ZhangQingrong on 2017/1/9.
     */
    private static class KeyUtils {

        public static RSAPrivateCrtKey getPriKey(String priKeyValue, String passWord) {
            //获取项目 相对路径
            InputStream inputStream = new ByteArrayInputStream(Base64.decodeBase64(priKeyValue));
            RSAPrivateCrtKey rsaPrivateCrtKey = getPriKey(inputStream, passWord);
            return rsaPrivateCrtKey;
        }

        public static RSAPrivateCrtKey getPriKey(File priKeyPath, String passWord) {
            //获取项目 相对路径
            try {
                FileInputStream inputStream = new FileInputStream(priKeyPath);
                RSAPrivateCrtKey rsaPrivateCrtKey = getPriKey(inputStream, passWord);
                return rsaPrivateCrtKey;
            } catch (FileNotFoundException e) {
                throw new RsaEncryException("getPriKey error", e);
            }
        }

        private static RSAPrivateCrtKey getPriKey(InputStream inputStream, String passWord) {
            //获取项目 相对路径
            String keyAlias = null;
            RSAPrivateCrtKey rsaPrikey = null;
            try {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(inputStream, passWord.toCharArray());
                Enumeration<?> myEnum = ks.aliases();
                while (myEnum.hasMoreElements()) {
                    keyAlias = (String) myEnum.nextElement();
                    if (ks.isKeyEntry(keyAlias)) {
                        rsaPrikey = (RSAPrivateCrtKey) ks.getKey(keyAlias, passWord.toCharArray());
                        break;
                    }
                }
            } catch (Exception e) {
                throw new RsaEncryException("getPriKey error", e);
            } finally {
                if (null != inputStream) {
                    try {
                        inputStream.close();
                    } catch (IOException e) {
                        throw new RsaEncryException("getPriKey error", e);
                    }
                }
            }
            return rsaPrikey;
        }

        public static X509Certificate getPublicKey(String pubKey) {
            InputStream inputStream = null;
            inputStream = new ByteArrayInputStream(Base64.decodeBase64(pubKey));
            X509Certificate x509Certificate = getPublicKey(inputStream);
            return x509Certificate;
        }

        public static X509Certificate getPublicKey(File pubKey) {
            try {
                FileInputStream fileInputStream = new FileInputStream(pubKey);
                X509Certificate x509Certificate = getPublicKey(fileInputStream);
                return x509Certificate;
            } catch (FileNotFoundException e) {
                throw new RsaEncryException("getPublicKey error", e);
            }
        }

        private static X509Certificate getPublicKey(InputStream inputStream) {
            X509Certificate x509cert = null;
            try {
                //实例化 x509
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                x509cert = (X509Certificate) cf.generateCertificate(inputStream);
            } catch (Exception e) {
                throw new RsaEncryException("getPublicKey error", e);
            } finally {
                if (inputStream != null) {
                    try {
                        inputStream.close();
                    } catch (IOException e) {
                        throw new RsaEncryException("getPublicKey error", e);
                    }
                }
            }
            //读取公钥
            return x509cert;
        }
    }

    /**
     * RSA 加解密异常
     *
     * @author ZhangQingrong
     * @date 2018/1/23 15:00
     */
    public static class RsaEncryException extends RuntimeException {

        public RsaEncryException(String message, Throwable cause) {
            super(message, cause);
        }
    }

}
