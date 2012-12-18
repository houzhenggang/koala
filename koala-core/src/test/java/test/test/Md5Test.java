package test.test;

import org.junit.Before;
import org.junit.Test;
import org.koala.util.MD5Tool;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.DigestInputStream;
import java.security.MessageDigest;

public class Md5Test {

    private MD5Tool mt;
    private MessageDigest md;
    private MessageDigest sd;

    @Before
    public void initValue() {
        try {
            mt = MD5Tool.getInstance();
            md = MessageDigest.getInstance("md5");
            sd = MessageDigest.getInstance("sha1");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testMd5() {
        try {
            md.update("fuck".getBytes());
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            buffer.put(md.digest());
            buffer.flip();
            while (buffer.hasRemaining()) {
                System.out.printf("%s ", Integer.toHexString(buffer.get() & 0xFF));
            }
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testFile() {

        try {
            StringBuilder builder = new StringBuilder();
            long start = System.currentTimeMillis();
            for (int i = 0; i < 2; i++) {
                builder.append(mt.handleFileInput(loadSelf()));
                builder.append("\n");
            }
            long end = System.currentTimeMillis();
            System.out.printf("Time use:%sms.\n", end - start);
            System.out.printf("md5:\n%s\n", builder.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testDigetStream() {
        try {
            InputStream in = new DigestInputStream(new FileInputStream(loadSelf()), sd);
            int b = -1;
            while ((b = in.read()) != -1) {
            }
            in.close();
            System.out.println(mt.byteArrayToHexString(sd.digest()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private File loadSelf() throws Exception {
        URI uri = this.getClass().getResource("../../aop.xml").toURI();
        System.out.printf("The path is %s.\n", uri.getPath());
        return new File(uri);
    }
}
