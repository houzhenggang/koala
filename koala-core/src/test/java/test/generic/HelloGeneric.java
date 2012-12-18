package test.generic;

import java.io.Serializable;
import org.springframework.stereotype.Service;

/**
 *
 * @author phoenixup
 */
@Service("HelloGeneric")
public class HelloGeneric<T extends Serializable> {

    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void sayHello(T t) {
        System.out.println(t.getClass().getName());
    }
}
