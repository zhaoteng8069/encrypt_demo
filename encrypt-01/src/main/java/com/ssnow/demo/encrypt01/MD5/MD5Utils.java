package com.ssnow.demo.encrypt01.MD5;

import sun.misc.BASE64Encoder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName MD5Utils
 * @Desc MD5信息摘要算法
 * @Author zhaoteng
 * @Date 2019/7/20 16:41
 * @Version 1.0
 **/
public class MD5Utils {

    private static final String MD5 = "MD5";

    /**
     * MD5 信息摘要
     * @param data 进行信息摘要的数据
     * @return 返回摘要字节数组
     * @throws NoSuchAlgorithmException 可能抛出的一场
     */
    public static byte[] digest(byte[] data) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(MD5).digest(data);
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        String str = "身上的水不想擦掉1";
        // 默认utf-8编码
        String encode = new BASE64Encoder().encode(digest(str.getBytes()));
        System.out.println(encode);

    }

}
