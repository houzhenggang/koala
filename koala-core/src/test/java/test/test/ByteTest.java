package test.test;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.util.List;

/**
 * @author YaFengLi
 */
public class ByteTest {

    public static final Logger logger = LoggerFactory.getLogger(ByteTest.class);

    @Test
    public void testByteOperation() {
        int k1 = -5 >>> 2;
        int k2 = -52 ^ 24;
        int k3 = -21 & 12;
        int k4 = -23 | 17;
        int k5 = 5 << 2;
        int k6 = 5 >> 1;
        int k7 = -5 >> 2;

        logger.info(Integer.toBinaryString(k1) + "|" + k1);
        logger.info(Integer.toBinaryString(k2) + "|" + k2);
        logger.info(Integer.toBinaryString(k3) + "|" + k3);
        logger.info(Integer.toBinaryString(k4) + "|" + k4);
        logger.info(Integer.toBinaryString(k5) + "|" + k5);
        logger.info(Integer.toBinaryString(k6) + "|" + k6);
        logger.info(Integer.toBinaryString(k7) + "|" + k7);
    }

    public <T extends Object> List<T> getItems(T firts) {
        return null;
    }
}

