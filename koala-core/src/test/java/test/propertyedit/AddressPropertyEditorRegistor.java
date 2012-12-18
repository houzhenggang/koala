/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package test.propertyedit;

import org.springframework.beans.PropertyEditorRegistrar;
import org.springframework.beans.PropertyEditorRegistry;

/**
 *
 * @author YaFengLi
 */
public class AddressPropertyEditorRegistor implements PropertyEditorRegistrar{

    public void registerCustomEditors(PropertyEditorRegistry registry) {
        registry.registerCustomEditor(Address.class,new AddressPropertyEditor());
    }


}
