package test.test;

import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import test.annotation.aop.HelloWorld;
import test.annotation.config.AnnotationPojo;
import test.annotation.config.PropertiesLoader;

public class AnnonationTest {

    private ApplicationContext ctx = null;

    public AnnonationTest() {
        ctx = new ClassPathXmlApplicationContext(new String[]{
                "META-INF/spring/applicationContext-common.xml", "META-INF/spring/applicationContext-aop.xml"});
    }

    @Test
    public void aop() {
        HelloWorld aop = (HelloWorld) ctx.getBean("helloworldaop");
        aop.sayHello("sh");
        aop.sayBefore("sb", 1);
        aop.sayAfter("sa", 2);
    }

    @Test
    public void annoation() {
        AnnotationPojo ap = (AnnotationPojo) ctx.getBean("annonationPojo");
        PropertiesLoader pl = (PropertiesLoader) ctx.getBean("propertiesLoader");
        ap.action();
        System.out.printf("[one,two,three,url,address] [%s,%s,%s,%s,%s]", pl.getOne(), pl.getTwo(), pl.getThree(), pl.getPicUrl(), pl.getPicAddress());
    }
}
