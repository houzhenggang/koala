/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.aop;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

/**
 *
 * @author YaFengLi
 */
public class HelloWorldInterceptorImpl implements MethodInterceptor {

    public Object invoke(MethodInvocation invocation) throws Throwable {
        System.out.println("[Before]");
        Object o = invocation.proceed();
        System.out.println("[After]");
        return o;
    }
}
