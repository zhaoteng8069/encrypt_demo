package com.ssnow.demo.encrypt01.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * @ClassName Base64Utils
 * @Desc Base64加密demo
 * @Author zhaoteng
 * @Date 2019/7/20 16:30
 * @Version 1.0
 **/
public class Base64Utils {

    /**
     * Base64编码
     * @param bytes 要编码的字节数组
     * @return 编码后的字符串
     */
    public static String encode(byte[] bytes) {
        return new BASE64Encoder().encode(bytes);
    }

    /**
     * Base64解码
     * @param str 需要解码的字符串
     * @return 解码后的字节数组
     * @throws IOException 可能抛出的异常
     */
    public static byte[] decode(String str) throws IOException {
        return new BASE64Decoder().decodeBuffer(str);
    }


    public static void main(String[] args) throws Exception {
        String str = "HELLO WORLD";

        String encode = encode(str.getBytes("UTF-8"));

        System.out.println(encode);

        String decode = new String (decode(encode),"UTF-8");

        System.out.println(decode);
    }

}
