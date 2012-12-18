package test.test;

import java.lang.reflect.Proxy;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import test.aop.HelloWorldImpl;
import test.aop.HelloWorld;
import test.aop.HelloWorldHandler;
import test.generic.HelloGeneric;

/**
 *
 * @author YaFengLi
 */
public class AopTest {

    public static final Logger logger=LoggerFactory.getLogger(AopTest.class);
    private AbstractApplicationContext ctx = null;

    @Before
    public void init() {
        ctx = new ClassPathXmlApplicationContext(new String[]{
                    "META-INF/spring/applicationContext-common.xml",
                    "META-INF/spring/applicationContext-generic.xml",
                    "META-INF/spring/applicationContext-aop_proxy.xml"
                });
    }

    @Test
    public void testAop() {
        HelloWorld hw = new HelloWorldImpl();
        HelloWorldHandler hwh = new HelloWorldHandler(hw);
        HelloWorld hwinstane = (HelloWorld) Proxy.newProxyInstance(hw.getClass().getClassLoader(), hw.getClass().getInterfaces(), hwh);
        System.out.println(hwinstane.sayHello("Fuck"));
    }

    @Test
    public void testProxy() {
        HelloWorld hw = (HelloWorld) ctx.getBean("helloWorldProxy");
        System.out.println(hw.sayHello("Test"));
    }

    @Test
    public void testGeneric() {
        HelloGeneric<Long> hgl=ctx.getBean("HelloGeneric",HelloGeneric.class);
        HelloGeneric<String> hgl2=ctx.getBean("helloGeneric_1",HelloGeneric.class);
        hgl.sayHello(Long.valueOf("123"));
        hgl2.sayHello("Fuck");
        logger.info("{},{}",hgl.getName(),hgl2.getName());
    }
}
