package test.test;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import test.dao.AccountMyBatisService;

/**
 *
 * @author phoenixup
 */
public class MyBatisTest {
    
    public static final Logger logger = LoggerFactory.getLogger(MyBatisTest.class);
    private ApplicationContext ctx;
    private AccountMyBatisService accountService;
    
    public MyBatisTest() {
        ctx = new ClassPathXmlApplicationContext("META-INF/spring/applicationContext-common.xml",
                "META-INF/spring/applicationContext-mybatis.xml");        
        logger.error("{}", ctx.getBeanDefinitionNames());
        accountService = ctx.getBean(AccountMyBatisService.class);
    }
    
    @Test
    public void testService() {
        logger.error("{}", accountService);
        accountService.service("234");
    }
}
