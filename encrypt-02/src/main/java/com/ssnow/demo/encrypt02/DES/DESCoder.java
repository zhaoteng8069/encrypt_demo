package com.ssnow.demo.encrypt02.DES;

import com.ssnow.demo.encrypt01.Base64.Base64Utils;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * @ClassName DESCoder
 * @Desc DES 对称加密算法
 * DES-Data Encryption Standard,即数据加密算法。
 * 是IBM公司于1975年研究成功并公开发表的。
 * DES算法的入口参数有三个:Key、Data、Mode。
 * 其中Key为8个字节共64位,是DES算法的工作密钥;Data也为8个字节64位,是要被加密或被解密的数据;
 * Mode为DES的工作方式,有两种:加密或解密。
 * DES算法把64位的明文输入块变为64位的密文输出块,它所使用的密钥也是64位。
 * @Author zhaoteng
 * @Date 2019/7/20 17:15
 * @Version 1.0
 **/
@Slf4j
public abstract class DESCoder{

    public static final String ALGORITHM = "DES";

    /**
     * 加密
     * @param data 加密的数据
     * @param key 密钥
     * @return 返回加密信息
     */
    public static byte[] encrypt(byte[] data, String key) throws Exception {
        Key secretKey = toKey(Base64Utils.decode(key));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * 解密
     * @param data 加密的数据
     * @param key 密钥
     * @return 解密后信息
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String key) throws Exception {
        Key secretKey = toKey(Base64Utils.decode(key));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * 密钥转换-返回DES密钥
     * @param key
     * @return
     * @throws Exception
     */
    private static Key toKey(byte[] key) throws Exception {
        DESKeySpec desKeySpec = new DESKeySpec(key);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = factory.generateSecret(desKeySpec);
        return secretKey;
    }

    /**
     * 获得密钥
     * @param seed
     * @return
     * @throws Exception
     */
    private static String initKey(String seed) throws Exception {
        SecureRandom secureRandom = null;
        if (seed == null) {
            secureRandom = new SecureRandom();
        } else {
            secureRandom = new SecureRandom(Base64Utils.decode(seed));
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64Utils.encode(secretKey.getEncoded());
    }

    public static void main(String[] args) throws Exception {
        String inputStr = "你好啊 世界";
        String key = initKey(null);
        log.info("原文：{}", inputStr);
        log.info("密钥：{}", key);
        byte[] encrypt = encrypt(inputStr.getBytes(), key);
        log.info("加密之后的信息：{}", Base64Utils.encode(encrypt));
        //解密
        byte[] decrypt = decrypt(encrypt, key);
        log.info("解密之后的信息：{}",new String(decrypt));
        Assert.assertEquals(inputStr, new String(decrypt));
    }


}
