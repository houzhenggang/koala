package test.test;

import org.junit.Test;
import org.koala.spring.support.DownloadUtil;

import java.io.File;
import java.io.RandomAccessFile;
import java.net.URL;

/**
 * @author annegu
 * @since 2009-07-16
 */
public class DownloadTest {

    @Test
    public void testDown() {
        String urlStr = "http://mirror.bjtu.edu.cn/apache//velocity/engine/1.7/velocity-1.7.zip";
        try {
            DownloadUtil downloadManager = new DownloadUtil();

            downloadManager.setUrl(new URL(urlStr));
            downloadManager.setFileDir("f:/");
            downloadManager.setSleepSeconds(5);
            String downladFileName = downloadManager.download();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

//    @Test
    public void testNumber() {
        File f = new File("f:/", "test.txt");
        try {
            RandomAccessFile raf = new RandomAccessFile(f, "r");
            int a = raf.readInt();
            int b = raf.readInt();
            int c = raf.readInt();

//            long b = raf.readLong();
            String s = raf.readLine();
//            long c = raf.length();
            System.out.printf("[%s,%s,%s,%s]\n", a, b, c, s);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
