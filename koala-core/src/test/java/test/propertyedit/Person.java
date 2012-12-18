/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package test.propertyedit;

/**
 *
 * @author YaFengLi
 */
public class Person {
    private String name;
    private Address address;

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
