/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.test;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import test.method.AwareLookup;
import test.method.AwareMethod;

/**
 *
 * @author YaFengLi
 */
public class MethodTest {

    private AbstractApplicationContext ctx = null;

    @Before
    public void before() {
        ctx = new ClassPathXmlApplicationContext(new String[]{"META-INF/spring/applicationContext-method.xml"});
    }

    @Test
    public void testMethod() {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i <= 5; i++) {
            buffer.append("****************");
        }
        AwareMethod am = null;
        for (int i = 0; i < 10; i++) {
            am = (AwareMethod) ctx.getBean("awareMethod");
            am.process();
        }
        System.out.println(buffer.toString());
        AwareLookup al = null;
        for (int i = 0; i < 10; i++) {
            al = (AwareLookup) ctx.getBean("awareLookup");
            al.process();
        }
        this.sayHello();
        this.sayHello("name","fuck");
    }

    public void sayHello(Object... args) {
        for (Object obj : args) {
            System.out.println(obj.toString());
        }
    }
}
