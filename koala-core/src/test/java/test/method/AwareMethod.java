/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.method;

import java.beans.PropertyEditorSupport;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;

/**
 *
 * @author YaFengLi
 */
public class AwareMethod extends PropertyEditorSupport implements BeanFactoryAware {

    private BeanFactory beanFactory;

    public void setBeanFactory(BeanFactory arg0) throws BeansException {
        this.beanFactory = arg0;
    }

    public Object process() {
        AwareBean ab = this.createBean();
        return ab.execute();
    }

    private AwareBean createBean() {
        return (AwareBean) this.beanFactory.getBean("awareBean");
    }
}
