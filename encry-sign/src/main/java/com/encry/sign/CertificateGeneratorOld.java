package com.encry.sign;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * 证书生成器
 *
 * @author ZhangQingrong
 * @date 2018/1/23 16:45
 */
public class CertificateGeneratorOld {

    public static final String KEY_STORE_TYPE_JKS = "jks";
    public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    public static final String SECURE_RANDOM_PROVIDER = "SUN";
    public static final String SIGN_ALGORITHM_SHA256 = "sha256WithRSA";
    public static final String SIGN_ALGORITHM_MD5 = "MD5withRSA";
    public static final String KEY_PAIR_ALGORITHM_RSA = "RSA";

    /**
     * 生成私钥
     * */
    public static void generateDigitalCert(KeyStoreInfo certInfo) {
        FileOutputStream out = null;
        try {
            SecureRandom sr = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, SECURE_RANDOM_PROVIDER);
            CertAndKeyGen cakg = new CertAndKeyGen(KEY_PAIR_ALGORITHM_RSA, SIGN_ALGORITHM_MD5);
            cakg.setRandom(sr);
            cakg.generate(2048);
            X500Name subject = new X500Name("CN=" + certInfo.getCN() + ",OU=" + certInfo.getOU() + ",O=" + certInfo.getO() + ",L=" + certInfo.getL() + ",ST=" + certInfo.getST() + ",C=" + certInfo.getC());
            X509Certificate certificate = cakg.getSelfCertificate(subject, certInfo.getStart(), certInfo.getValidityDays() * 24L * 60L * 60L);
            KeyStore outStore = KeyStore.getInstance(KEY_STORE_TYPE_JKS);
            outStore.load(null, certInfo.getKeyStorePass().toCharArray());
            outStore.setKeyEntry(certInfo.getAlias(), cakg.getPrivateKey(), certInfo.getKeyStorePass().toCharArray(), new java.security.cert.Certificate[]{certificate});
            out = new FileOutputStream(certInfo.getPrivateKeyPath());
            outStore.store(out, certInfo.getKeyStorePass().toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) {
                    out.close();
                    out = null;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    /**
     * 导出公钥
     * */
    public static void exportPublicKeyCertificate(KeyStoreInfo certInfo) {
        FileOutputStream fos = null;
        FileInputStream fis = null;
        try {
            KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE_JKS);
            fis = new FileInputStream(certInfo.getPrivateKeyPath());
            ks.load(fis, certInfo.getKeyStorePass().toCharArray());
            java.security.cert.Certificate cert = ks.getCertificate(certInfo.getAlias());
            fos = new FileOutputStream(certInfo.getPublicKeyPath());
            fos.write(cert.getEncoded());
            fos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    /**
     * 证书库信息
     *
     * @author ZhangQingrong
     * @date 2018/1/23 15:19
     */
    public static class KeyStoreInfo {
        /**
         * country（国家）
         */
        private String C;
        /**
         * Organization（组织）
         */
        private String O;
        /**
         * OrganizationUnit（组织单位）
         */
        private String OU;
        /**
         * State or Province Name （省份）
         */
        private String ST;
        /**
         * Locality（地区）
         */
        private String L;
        /**
         * common name (通用名)
         */
        private String CN;
        /**
         * 开始时间
         */
        private Date start;
        /**
         * 有效时间，单位：天
         */
        private long validityDays;
        /**
         * 证书名称
         */
        private String alias;
        /**
         * 证书库密码
         */
        private String keyStorePass;
        /**
         * 私钥路径
         */
        private String privateKeyPath;
        /**
         * 公钥路径
         */
        private String publicKeyPath;

        public KeyStoreInfo() {
        }

        public String getC() {
            return C;
        }

        public void setC(String c) {
            C = c;
        }

        public String getO() {
            return O;
        }

        public void setO(String o) {
            O = o;
        }

        public String getOU() {
            return OU;
        }

        public void setOU(String OU) {
            this.OU = OU;
        }

        public String getST() {
            return ST;
        }

        public void setST(String ST) {
            this.ST = ST;
        }

        public String getL() {
            return L;
        }

        public void setL(String l) {
            L = l;
        }

        public String getCN() {
            return CN;
        }

        public void setCN(String CN) {
            this.CN = CN;
        }

        public Date getStart() {
            return start;
        }

        public void setStart(Date start) {
            this.start = start;
        }

        public long getValidityDays() {
            return validityDays;
        }

        public void setValidityDays(long validityDays) {
            this.validityDays = validityDays;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getKeyStorePass() {
            return keyStorePass;
        }

        public void setKeyStorePass(String keyStorePass) {
            this.keyStorePass = keyStorePass;
        }

        public String getPrivateKeyPath() {
            return privateKeyPath;
        }

        public void setPrivateKeyPath(String privateKeyPath) {
            this.privateKeyPath = privateKeyPath;
        }

        public String getPublicKeyPath() {
            return publicKeyPath;
        }

        public void setPublicKeyPath(String publicKeyPath) {
            this.publicKeyPath = publicKeyPath;
        }
    }

    public static void main(String[] args) {
        KeyStoreInfo certInfo = new KeyStoreInfo();
        certInfo.setC("CHINA");
        certInfo.setST("GUANGDONG");
        certInfo.setL("GUANGZHOU");
        certInfo.setO("FASTBANK");
        certInfo.setOU("MinTech");
        certInfo.setCN("www.fastbank.net");
        certInfo.setStart(new Date());
        certInfo.setValidityDays(365);
        certInfo.setAlias("快银支付");
        certInfo.setKeyStorePass("123456789");
        certInfo.setPrivateKeyPath("E:/fastbank_001.ks");
        certInfo.setPublicKeyPath("E:/fastbank_001.cer");

        generateDigitalCert(certInfo);
        System.out.println("生成证书成功");
        exportPublicKeyCertificate(certInfo);
        System.out.println("导出公钥成功");
    }
}
