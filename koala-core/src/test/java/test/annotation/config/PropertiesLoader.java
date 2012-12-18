package test.annotation.config;

import java.io.Serializable;

import org.koala.spring.annotation.Properties;
import org.springframework.stereotype.Service;

/**
 * @author YaFengLi
 * 
 */
@Service("propertiesLoader")
public class PropertiesLoader implements Serializable {

    @Properties(name = "pic.address")
    private String picAddress;
    @Properties(name = "pic.url")
    private String picUrl;
    @Properties(name = "one")
    private String one;
    @Properties(name = "two")
    private String two;
    @Properties(name = "three")
    private String three;

    public String getOne() {
        return one;
    }

    public void setOne(String one) {
        this.one = one;
    }

    public String getThree() {
        return three;
    }

    public void setThree(String three) {
        this.three = three;
    }

    public String getTwo() {
        return two;
    }

    public void setTwo(String two) {
        this.two = two;
    }

    public String getPicAddress() {
        return picAddress;
    }

    public void setPicAddress(String picAddress) {
        this.picAddress = picAddress;
    }

    public String getPicUrl() {
        return picUrl;
    }

    public void setPicUrl(String picUrl) {
        this.picUrl = picUrl;
    }
}
