/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.aop;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/**
 *
 * @author YaFengLi
 */
public class HelloWorldHandler implements InvocationHandler {
    private HelloWorld hw;
    public HelloWorldHandler(HelloWorld hw){
        this.hw=hw;
    }


    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        System.out.println(proxy.getClass());
        System.out.println("[Before]");
        Object o = method.invoke(hw, args);
        System.out.println("[After]");
        return o;
    }
}
