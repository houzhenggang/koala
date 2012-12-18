package test.memcached;


import net.rubyeye.xmemcached.MemcachedClient;
import net.rubyeye.xmemcached.XMemcachedClient;
import net.rubyeye.xmemcached.utils.AddrUtil;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class XmcTest {
    public static final Logger logger = LoggerFactory.getLogger(XmcTest.class);

    private static ApplicationContext ctx;

    @BeforeClass
    public static void init() {
        ctx = new ClassPathXmlApplicationContext(new String[]{"META-INF/spring/applicationContext-xmc.xml"});
    }

    private void process(MemcachedClient mc) throws Exception {
        ExecutorService service = Executors.newFixedThreadPool(20);
        List<Future<Long>> list = new ArrayList<Future<Long>>();
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10; i++) {
            list.add(service.submit(new XmcProcess(mc)));
        }
        for (Future<Long> future : list) {
            while (!future.isDone()) {
                Thread.sleep(3000);
            }
            logger.error("#waiting...{}.", future.get());
        }
        long end = System.currentTimeMillis();
        logger.error("#all time is {}#.", new Object[]{end - start});
    }


    @Test
    public void testBean() {
        try {
            MemcachedClient mc = new XMemcachedClient(AddrUtil.getAddresses("192.168.2.237:8765"));
            process(mc);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testCtx() {
        try {
            MemcachedClient mc = ctx.getBean("memcachedClient", XMemcachedClient.class);
            process(mc);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    class XmcProcess implements Callable<Long> {
        private MemcachedClient mc;

        XmcProcess(MemcachedClient mc) {
            this.mc = mc;
        }

        @Override
        public Long call() throws Exception {
            run();
            return Thread.currentThread().getId();
        }

        public void run() {
            StringBuilder builder = new StringBuilder();
            long start = System.currentTimeMillis();
            try {
                for (int i = 0; i < 200; i++) {
                    String key = "test" + i;
                    mc.set(key, 3000, String.valueOf(System.currentTimeMillis()));
                    String val = mc.get(key, 2000);
                    builder.append(key);
                    builder.append("=");
                    builder.append(val);
                    builder.append("\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            long end = System.currentTimeMillis();
            logger.error("#{},{}#.", new Object[]{Thread.currentThread().getId(), end - start});
        }
    }
}


