package test.test;

import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;

/**
 * @author liyafeng 这是CRC的测试程序！
 */
public class CRCTest {
    public static String name = "18992";

    public CRCTest() {
    }

    @Test
    public void testCrc32() {
        CRC32 crc32 = new CRC32();
        crc32.update(name.getBytes());
        System.out.printf("crc32(%s)=%s\n", name, crc32.getValue());
        crc32.reset();
        try {
            CheckedInputStream cis = new CheckedInputStream(new FileInputStream(new File("pom.xml")), crc32);
            byte[] tempBuf = new byte[1024];
            while (cis.read(tempBuf) >= 0) {}
            System.out.println("crcfile(pom.xml)=" + cis.getChecksum().getValue());
            cis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void test() {

        Long l = Long.decode(name);
        String str = Long.toHexString(l ^ 0x55aa55aa);
        System.out.printf("the name is %s ,the l is %s,the str is %s\n", name, l, str);
    }

    @Test
    public void testhex() {
        String ip = "218.94.84.92";
        System.out.printf("the tohex is %s\n", getIpDecode(ip));
    }

    private String getIpDecode(String ip) {
        byte[] b = getIpByteArrayFromString(ip);
        System.out.printf("[b]%d,%d,%d,%d\n", b[0], b[1], b[2], b[3]);
        String ipstr = toHexString(b);
        System.out.printf("[ipstr]%s\n", ipstr);
        ipstr = "0x" + ipstr;
        System.out.printf("[ipstr]%s\n", ipstr);
        ipstr = Long.toHexString(Long.decode(ipstr) ^ 0x55aa55aa);
        System.out.printf("[ipstr]%s\n", ipstr);
        ipstr = "0x" + ipstr;
        System.out.printf("[ipstr]%s\n", ipstr);
        String iplong = Long.decode(ipstr).toString();
        System.out.printf("[iplong]%s\n", iplong);
        return iplong;
    }

    private String toHexString(byte[] buf) {
        int i = 0;
        String s = "";
        for (i = 0; i < buf.length; i++) {
            s = toHex2(buf[i]) + s;
        }
        return s;
    }

    private String toHex2(byte buf) {
        int n = buf >= 0 ? buf : 256 + buf;
        String str = Integer.toHexString(n);
        if (str.length() == 1) {
            str = "0" + str;
        }
        return str;
    }

    private byte[] getIpByteArrayFromString(String ip) {
        byte[] ret = new byte[4];
        java.util.StringTokenizer st = new java.util.StringTokenizer(ip, ".");
        try {
            ret[0] = (byte) (Integer.parseInt(st.nextToken()) & 0xFF);
            ret[1] = (byte) (Integer.parseInt(st.nextToken()) & 0xFF);
            ret[2] = (byte) (Integer.parseInt(st.nextToken()) & 0xFF);
            ret[3] = (byte) (Integer.parseInt(st.nextToken()) & 0xFF);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return ret;
    }
}
