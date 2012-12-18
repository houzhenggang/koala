/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.method;

/**
 *
 * @author YaFengLi
 */
public abstract class AwareLookup {

    public Object process() {
        AwareBean ab = this.createBean();
        return ab.execute();
    }

    public abstract AwareBean createBean();
}
