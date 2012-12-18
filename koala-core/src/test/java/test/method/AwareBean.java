/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.method;

/**
 *
 * @author YaFengLi
 */
public class AwareBean {

    public static int instance_num = 0;
    private String id;
    private Integer count;

    public AwareBean() {
        instance_num++;
    }

    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String execute() {
        System.out.printf("[AwareBean is ok.][%d]\n",AwareBean.instance_num);
        return null;
    }    
}
