package com.ssnow.demo.encrypt01.SHA;

import sun.misc.BASE64Encoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName ShaUtils
 * @Desc SHA 安全散列算法
 * @Author zhaoteng
 * @Date 2019/7/20 16:51
 * @Version 1.0
 **/
public class ShaUtils {

    private static final String SHA = "SHA";

    /**
     * SHA 安全散列算法
     * @param data 进行散列的数据
     * @return 返回三列之后的数据
     * @throws NoSuchAlgorithmException 可能抛出的异常
     */
    public static byte[] digest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(SHA);
        return md.digest(data);
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        String str = "身上的水不想擦掉";
        // 默认utf-8编码
        String encode = new BASE64Encoder().encode(digest(str.getBytes()));
        System.out.println(encode);
    }
}
