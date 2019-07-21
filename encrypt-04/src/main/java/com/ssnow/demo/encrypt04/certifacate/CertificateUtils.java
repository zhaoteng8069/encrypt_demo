package com.ssnow.demo.encrypt04.certifacate;

import com.ssnow.demo.encrypt01.Base64.Base64Utils;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @ClassName CertificateUtils
 * @Desc 证书工具类
 * @Author zhaoteng
 * @Date 2019/7/20 19:44
 * @Version 1.0
 **/
@Slf4j
public class CertificateUtils {

    /**
     * Java密钥库(Java Key Store，JKS)KEY_STORE
     */
    public static final String KEY_STORE = "JKS";

    public static final String X509 = "X.509";

    /**
     * 私钥签名
     * @param data 加密数据
     * @param keyStorePath keyStore存放位置
     * @param alias 别名
     * @param password 密码
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String keyStorePath, String alias, String password) throws Exception {
       /* KeyStore keyStore = getKeyStore(keyStorePath, password);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());

        Signature signature = Signature.getInstance(privateKey.getAlgorithm());
        signature.initSign(privateKey);
        signature.update(data);
        return Base64Utils.encode(signature.sign());*/
        X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath, alias, password);
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initSign(privateKey);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }

    /**
     * 公钥验签
     * @param data 加密数据
     * @param certificatePath 证书地址
     * @param sign 签名
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] data, String certificatePath, String sign) throws Exception {
        /*Certificate certificate = getCertificate(certificatePath);
        PublicKey publicKey = certificate.getPublicKey();
        Signature signature = Signature.getInstance(publicKey.getAlgorithm());
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));*/
        // 获得证书
        X509Certificate x509Certificate = (X509Certificate) getCertificate(certificatePath);
        // 获得公钥
        PublicKey publicKey = x509Certificate.getPublicKey();
        // 构建签名
        Signature signature = Signature.getInstance(x509Certificate
                .getSigAlgName());
        signature.initVerify(publicKey);
        signature.update(data);

        return signature.verify(Base64Utils.decode(sign));
    }

    /**
     * 私钥加密
     * @param data 原始数据
     * @param keyStorePath keyStore
     * @param alias
     * @param password
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPri(byte[] data, String keyStorePath, String alias, String password) throws Exception {
        PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     * @param data
     * @param certificatePath
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPub(byte[] data, String certificatePath) throws Exception {
        Certificate certificate = getCertificate(certificatePath);
        PublicKey publicKey = certificate.getPublicKey();
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 公钥加密
     * @param data 原始数据
     * @param certificatePath 证书存放路径
     * @return 加密数据
     * @throws Exception
     */
    public static byte[] encryptByPub(byte[] data, String certificatePath) throws Exception {
        PublicKey publicKey = getPublicKey(certificatePath);
        Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }


    /**
     * 私钥解密
     * @param data 加密数据
     * @param keyStorePath keyStore路径
     * @param alias 证书别名
     * @param password 密码
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPri(byte[] data, String keyStorePath ,
                                      String alias , String password) throws Exception {
        PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 获得私钥（通过KeyStore）
     * @param keyStorePath
     * @param alias
     * @param password
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String keyStorePath, String alias, String password) throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    /**
     * 根据证书获取公钥
     * @param certificatePath 证书存放路径
     * @return 公钥
     * @throws Exception
     */
    public static PublicKey getPublicKey(String certificatePath) throws Exception {
        Certificate certificate = getCertificate(certificatePath);
        return certificate.getPublicKey();
    }

    /**
     * 加载证书
     * @param path 证书存放路径
     * @return 证书
     * @throws Exception
     */
    public static Certificate getCertificate(String path) throws Exception {
        FileInputStream in = null;
        try {
            CertificateFactory factory = CertificateFactory.getInstance(X509);
            in = new FileInputStream(path);
            return factory.generateCertificate(in);
        } catch (Exception e) {
            throw e;
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }

    /**
     * 获取证书
     * @param keyStorePath keyStore路径
     * @param alias 别名
     * @param password 密码
     * @return
     * @throws Exception
     */
    public static Certificate getCertificate(String keyStorePath, String alias, String password) throws Exception {
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        return  keyStore.getCertificate(alias);
    }

    /**
     * 验证证书的有效性
     * @param date 时间
     * @param path 证书路径
     * @return
     * @throws Exception
     */
    public static boolean verifyCertificate(Date date, String path) {
        boolean status = true;
        try {
            X509Certificate x509Certificate = (X509Certificate) getCertificate(path);
            x509Certificate.checkValidity(date);
        } catch (Exception e) {
            status = false;
            // demo中的处理逻辑
            log.error(e.getMessage(), e);
        }
        return status;
    }

    /**
     * 获取KeyStore
     * @param keyStorePath 路径
     * @param password 密码
     * @return
     * @throws Exception
     */
    public static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {
        FileInputStream in = null;
        try {
            in = new FileInputStream(keyStorePath);
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
            keyStore.load(in, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw e;
        } finally {
            if (in != null) {
                in.close();
            }
        }
    }


    public static void main(String[] args) throws Exception {
        String alias = "www.zlex.com";
        String password = "123456";
        String string = "证书加密机制";

        String certificatePath = "D:\\IDEA\\2018.3\\workspace\\encrypt_workspace\\zlex.cer";
        String keyStorePath = "D:\\IDEA\\2018.3\\workspace\\encrypt_workspace\\zlex.keystore";
        // 1. 公钥加密
        // byte[] encryptByPub = encryptByPub(string.getBytes(), certificatePath);
        // 2. 私钥解密
        // byte[] decryptByPri = decryptByPri(encryptByPub, keyStorePath, alias, password);

        // log.info("解密后的数据：{}", new String(decryptByPri));
        // 3. 验证数据一致性
        // Assert.assertArrayEquals(string.getBytes(), decryptByPri);

        // 4. 验证证书有效
        // Assert.assertTrue(verifyCertificate(new Date(), certificatePath));

        // 1. 私钥加密
        byte[] encryptByPri = encryptByPri(string.getBytes(), keyStorePath, alias, password);
        // 2. 公钥解密
        byte[] decryptByPub = decryptByPub(encryptByPri, certificatePath);

        log.info("公钥解密后的数据：{}", new String(decryptByPub));
        // 3. 私钥签名
        String sign = sign(encryptByPri, keyStorePath, alias, password);
        // 4. 公钥验签
        boolean verify = verify(encryptByPri, certificatePath, sign);
        Assert.assertTrue(verify);
    }

}
