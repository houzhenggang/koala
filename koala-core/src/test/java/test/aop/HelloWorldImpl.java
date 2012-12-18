/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.aop;

/**
 *
 * @author YaFengLi
 */
public class HelloWorldImpl implements HelloWorld {

    public String sayHello(String name) {
        System.out.printf("Hello World ,Mr. [%s]\n", name);
        return name;
    }
}
