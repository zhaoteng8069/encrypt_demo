package com.ssnow.demo.encrypt03.RSA;

import com.ssnow.demo.encrypt01.Base64.Base64Utils;
import lombok.extern.slf4j.Slf4j;
import org.junit.Assert;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName RSAUtils
 * @Desc RSA 非对称加密算法
 * 这种算法1978年就出现了，它是第一个既能用于数据加密也能用于数字签名的算法。
 * 它易于理解和操作，也很流行。算法的名字以发明者的名字命名：Ron Rivest, AdiShamir 和Leonard Adleman。
 * 这种加密算法的特点主要是密钥的变化，RSA同时有两把钥匙，公钥与私钥。
 * 同时支持数字签名。数字签名的意义在于，对传输过来的数据进行校验。确保数据在传输工程中不被修改
 * <p>
 * 流程分析：
 * <p>
 * 甲方构建密钥对儿，将公钥公布给乙方，将私钥保留。
 * 甲方使用私钥加密数据，然后用私钥对加密后的数据签名，发送给乙方签名以及加密后的数据；
 * 乙方使用公钥、签名来验证待解密数据是否有效，如果有效使用公钥对数据解密。
 * 乙方使用公钥加密数据，向甲方发送经过加密后的数据；甲方获得加密数据，通过私钥解密。
 *
 * 总结：
 *  简要总结一下，使用公钥加密、私钥解密，完成了乙方到甲方的一次数据传递，通过私钥加密、公钥解密，
 *  同时通过私钥签名、公钥验证签名，完成了一次甲方到乙方的数据传递与验证，两次数据传递完成一整套的数据交互！
 * @Author zhaoteng
 * @Date 2019/7/20 17:55
 * @Version 1.0
 **/
@Slf4j
public class RSAUtils {

    public static final String KEY_ALGORITHM = "RSA";

    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    private static final String PUBLIC_KEY = "RSAPublicKey";

    private static final String PRIVATE_KEY = "RSAPrivateKey";


    /**
     * 私钥签名
     * @param data 加密数据
     * @param key 私钥
     * @return
     */
    public static String sign(byte[] data,String key) throws Exception{
        //对私钥解码
        byte[] decode = Base64Utils.decode(key);
        // 获取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }

    /**
     * 公钥验签
     * @param data 加密数据
     * @param key 公钥
     * @param sign 数字签名
     * @return
     */
    public static boolean verify(byte[] data , String key, String sign) throws Exception {
        byte[] decode = Base64Utils.decode(key);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));
    }


    /**
     * 公钥解密
     * @param data 加密的数据
     * @param key 公钥
     * @return
     */
    public static byte[] decryptByPub(byte[] data,String key) throws Exception {
        // 公钥解码
        byte[] decode = Base64Utils.decode(key);
        // 获取公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        // cipher 加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥加密
     * @param data 原始数据
     * @param key 私钥
     * @return
     */
    public static byte[] encryptByPri(byte[] data , String key) throws Exception {
        // 私钥解码
        byte[] decode = Base64Utils.decode(key);
        // 获取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        // cipher 加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 私钥解密
     * @param data 加密的数据
     * @param key 私钥
     * @return
     */
    public static byte[] decryptByPri(byte[] data , String key) throws Exception {
        // 对私钥解码
        byte[] decode = Base64Utils.decode(key);
        // 获取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decode);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        // 用cipher对数据进行解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * 公钥加密
     * @param data 原始数据
     * @param key 公钥
     * @return
     */
    public static byte[] encryptByPub(byte[] data , String key) throws Exception {
        // 公钥解码
        byte[] decode = Base64Utils.decode(key);
        // 获得公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decode);
        KeyFactory factory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = factory.generatePublic(x509EncodedKeySpec);

        // 使用cipher对数据加密
        Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 初始化RSA密钥对
     * @return
     * @throws Exception
     */
    private static Map<String, Object> initKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // 公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        // 私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> map = new HashMap<>();
        map.put(PUBLIC_KEY, publicKey);
        map.put(PRIVATE_KEY, privateKey);
        return map;
    }


    public static void main(String[] args) throws Exception {

        Map<String, Object> map = initKey();
        // 0. 原始数据
        String string = "我是原始数据";
        // 1. 获取公钥
        RSAPublicKey publicKey = (RSAPublicKey) map.get(PUBLIC_KEY);
        // 2. 获得私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) map.get(PRIVATE_KEY);
        // 3. 公钥加密
        // byte[] encryptByPub = encryptByPub(string.getBytes(), Base64Utils.encode(publicKey.getEncoded()));
        // 4. 私钥解密
        // byte[] decryptByPri = decryptByPri(encryptByPub, Base64Utils.encode(privateKey.getEncoded()));
        // log.info("原始数据：{}", string);
        // log.info("解密后的数据：{}", new String(decryptByPri));
        // 5. 私钥加密
        byte[] encryptByPri = encryptByPri(string.getBytes(), Base64Utils.encode(privateKey.getEncoded()));
        // 6. 公钥解密
        byte[] decryptByPub = decryptByPub(encryptByPri, Base64Utils.encode(publicKey.getEncoded()));
        log.info("解密后的数据：{}",new String(decryptByPub));
        // 7. 私钥签名
        String sign = sign(encryptByPri, Base64Utils.encode(privateKey.getEncoded()));
        // 8. 公钥验签
        boolean verify = verify(encryptByPri, Base64Utils.encode(publicKey.getEncoded()), sign);

        Assert.assertEquals(true, verify);

    }

}
