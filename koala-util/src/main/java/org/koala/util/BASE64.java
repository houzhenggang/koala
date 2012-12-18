package org.koala.util;

import java.io.UnsupportedEncodingException;

/**
 * <p>Base64的Java实现</p>
 * @author YaFengLi
 * @version 1.0
 * @since 1.0
 */
public class BASE64 {

    public static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toCharArray();
    public static final byte[] CODES = new byte[256];

    static {
        for (int i = 0; i < 256; i++) {
            CODES[i] = -1;
        }
        for (int i = 'A'; i <= 'Z'; i++) {
            CODES[i] = (byte) (i - 'A');
        }
        for (int i = 'a'; i <= 'z'; i++) {
            CODES[i] = (byte) (26 + i - 'a');
        }
        for (int i = '0'; i <= '9'; i++) {
            CODES[i] = (byte) (52 + i - '0');
        }
        CODES['+'] = 62;
        CODES['/'] = 63;
    }

    /**
     * 对字节数组编码
     * @param data 需要编码的字节数组
     * @return 返回编码后的字符数组
     */
    public static char[] encode(byte[] data) {
        char[] out = new char[((data.length + 2) / 3) * 4];

        for (int i = 0, index = 0; i < data.length; i += 3, index += 4) {
            boolean quad = false;
            boolean trip = false;
            int val = (0xFF & (int) data[i]);
            val <<= 8;
            if ((i + 1) < data.length) {
                val |= (0xFF & (int) data[i + 1]);
                trip = true;
            }
            val <<= 8;
            if ((i + 2) < data.length) {
                val |= (0xFF & (int) data[i + 2]);
                quad = true;
            }
            out[index + 3] = ALPHABET[(quad ? (val & 0x3F) : 64)];
            val >>= 6;
            out[index + 2] = ALPHABET[(trip ? (val & 0x3F) : 64)];
            val >>= 6;
            out[index + 1] = ALPHABET[val & 0x3F];
            val >>= 6;
            out[index + 0] = ALPHABET[val & 0x3F];
        }
        return out;
    }

    /**
     * 对给定编码格式的字符串编码
     * @param dataStr 需要编码的字符串
     * @param charset 字符串编码
     * @return 返回编码后的字符数组
     * @throws UnsupportedEncodingException 
     */
    public static char[] encode(String dataStr, String charset) throws UnsupportedEncodingException {
        return encode(dataStr.getBytes(charset));
    }

    /**
     * 对给定的字符串编码
     * @param dataStr 需要编码的字符串
     * @return 返回编码后的字符数组
     */
    public static char[] encode(String dataStr) {
        return encode(dataStr.getBytes());
    }

    /**
     * 对字符数组解码
     * @param data 需要解码的字符素组
     * @return 返回解码后的字节数组
     */
    public static byte[] decode(char[] data) {
        int len = ((data.length + 3) / 4) * 3;
        if (data.length > 0 && data[data.length - 1] == '=') {
            --len;
        }
        if (data.length > 1 && data[data.length - 2] == '=') {
            --len;
        }
        byte[] out = new byte[len];
        int shift = 0;
        int accum = 0;
        int index = 0;
        for (int ix = 0; ix < data.length; ix++) {
            int value = CODES[data[ix] & 0xFF];
            if (value >= 0) {
                accum <<= 6;
                shift += 6;
                accum |= value;
                if (shift >= 8) {
                    shift -= 8;
                    out[index++] = (byte) ((accum >> shift) & 0xff);
                }
            }
        }
        if (index != out.length) {
            throw new Error("miscalculated data length!");
        }
        return out;
    }

    /**
     * 对字符数组解码
     * @param dataStr 需要解码的字符串
     * @return 返回解码后的字节数组
     */
    public static byte[] decode(String dataStr) {
        return decode(dataStr.toCharArray());
    }
}
