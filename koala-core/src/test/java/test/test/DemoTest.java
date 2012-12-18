package test.test;

import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DemoTest {
    public static final String KEY_ALGORITHM = "HmacMD5";//算法
    public static final String CHARSET = "UTF-8";//字符编码格式
    public static final String keyStr = "sdgreennet";//密钥字符串

    /**
     * @param bts byte数组
     * @return 讲byte数组转换成Hex字符串
     */
    private String bytesToHex(byte[] bts) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < bts.length; i++) {
            int value = bts[i] & 0xFF;
            if (value >= 0x10) {
                buffer.append(Integer.toHexString(value));
            } else {
                buffer.append("0");
                buffer.append(Integer.toHexString(value));
            }
        }
        return buffer.toString();
    }

    /**
     * @param keyStr  密钥字符串
     * @param content 需要加密字符串
     * @return 加密后的校验字符串
     * @throws Exception
     */
    private String checkSum(String keyStr, String content) throws Exception {
        SecretKey key = new SecretKeySpec(keyStr.getBytes(), KEY_ALGORITHM);
        if (key != null) {
            Mac mac = Mac.getInstance(key.getAlgorithm());
            mac.init(key);
            mac.update(content.getBytes(CHARSET));
            byte[] bts = mac.doFinal();
            return bytesToHex(bts);
        } else {
            throw new Exception("ERROR:KEY IS NULL.");
        }
    }

    @Test
    public void testCheckSum() {
        String keyStr = "sdgreennet";
        String content = "sdtest1$12345678$test123";
        try {
            System.out.printf("key:%s\ncontent:%s\nsum:%s\n", keyStr, content, checkSum(keyStr, content));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
