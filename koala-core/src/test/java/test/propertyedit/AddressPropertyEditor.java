/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package test.propertyedit;

import java.beans.PropertyEditorSupport;
import org.springframework.util.StringUtils;

/**
 *
 * @author YaFengLi
 */
public class AddressPropertyEditor extends PropertyEditorSupport {

    @Override
    public String getAsText() {
        return this.getValue().toString();
    }

    @Override
    public void setAsText(String text) throws IllegalArgumentException {
        System.out.println("Come on,Come on!");
        Address add = null;
        if (text != null) {
            String[] attrs = StringUtils.tokenizeToStringArray(text, ",");
            add = new Address();
            add.setStreet(attrs[0]);
            add.setDoorNum(attrs[1]);
            add.setPostCode(attrs[2]);
            this.setValue(add);
        }
    }
}
