package com.encry.sign;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author ZhangQingrong
 * @date 2018/1/24 10:08
 */
public class CertificateGenerator {

    public static void main(String[] args) {
        try {
            //获取公私钥对
            KeyPair keyPair = getKeyPair();
            //获取证书构建器
            X509v3CertificateBuilder certificateBuilder = getCertificateBuilder(keyPair);
            //获取证书签名器
            ContentSigner contentSigner = getContentSigner(keyPair);
            //生成证书
            X509Certificate x509Certificate = getX509Certificate(certificateBuilder, contentSigner);

            //导出私钥
            String password = "123456";
            String privateKeyPath = "E:/test.ks";
            storePrivateKey(password, privateKeyPath, x509Certificate, keyPair);
            //导出公钥
            String publicKeyPath = "E:/test.cer";
            storePublicKey(publicKeyPath,x509Certificate);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 获取公私钥对
     */
    private static KeyPair getKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        //添加BC的安全模式
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        //生成公私钥对
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        return keyPair;
    }

    /**
     * 获取证书构建器
     */
    private static X509v3CertificateBuilder getCertificateBuilder(KeyPair keyPair) {
        X500Name issuerX500Name = getIssuerX500Name();
        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = DateUtils.addYears(new Date(), 1);
        X500Name subjectX500Name = getSubjectX500Name();
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerX500Name, serial, notBefore, notAfter, subjectX500Name, publicKeyInfo);
        return certBuilder;
    }

    /**
     * 获取证书签名器
     */
    private static ContentSigner getContentSigner(KeyPair keyPair) throws OperatorCreationException {
        //指定签名算法
        //String signatureAlgorithm  = "Sha1withRSA";
        String signatureAlgorithm = "MD5withRSA";
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
        return contentSigner;
    }

    /**
     * 生成证书
     */
    private static X509Certificate getX509Certificate(X509v3CertificateBuilder certificateBuilder, ContentSigner contentSigner) throws CertificateException {
        X509CertificateHolder certHolder = certificateBuilder.build(contentSigner);
        X509Certificate x509Certificate = (new JcaX509CertificateConverter()).getCertificate(certHolder);
        return x509Certificate;
    }

    /**
     * 存储私钥
     */
    private static void storePrivateKey(String password, String privateKeyPath, X509Certificate x509Certificate, KeyPair keyPair) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, password.toCharArray());
        store.setKeyEntry("fastbank", keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{x509Certificate});
        store.store(new FileOutputStream(new File(privateKeyPath)), password.toCharArray());
    }

    /**
     * 存储公钥
     */
    private static void storePublicKey(String publicKeyPath, X509Certificate x509Certificate) throws CertificateEncodingException, IOException {
        FileUtils.writeByteArrayToFile(new File(publicKeyPath), x509Certificate.getEncoded());
    }

    /**
     * 发行者信息
     */
    private static X500Name getIssuerX500Name() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.C, "CN");
        x500NameBuilder.addRDN(BCStyle.ST, "GUANGDONG");
        x500NameBuilder.addRDN(BCStyle.L, "GUANGZHOU");
        x500NameBuilder.addRDN(BCStyle.O, "FASTBANK");
        x500NameBuilder.addRDN(BCStyle.OU, "MinTech");
        x500NameBuilder.addRDN(BCStyle.CN, "www.fastbank.net");
        return x500NameBuilder.build();
    }

    /**
     * 使用者信息
     */
    private static X500Name getSubjectX500Name() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.C, "CN");
        x500NameBuilder.addRDN(BCStyle.ST, "GUANGDONG");
        x500NameBuilder.addRDN(BCStyle.L, "GUANGZHOU");
        x500NameBuilder.addRDN(BCStyle.O, "MERCHANT");
        x500NameBuilder.addRDN(BCStyle.OU, "MinTech");
        x500NameBuilder.addRDN(BCStyle.CN, "MERCHANT_001");
        return x500NameBuilder.build();
    }
}
