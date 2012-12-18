package test.test;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import test.propertyedit.Person;

import java.util.Iterator;
import java.util.TreeMap;
import java.util.SortedMap;

/**
 * Date: 2009-08-01
 * Time: 11:02
 *
 * @author YaFengLi
 * @version 1.0
 */
public class PropertyTest {

    private AbstractApplicationContext ctx = null;

    @Before
    public void init() {
        ctx = new ClassPathXmlApplicationContext(new String[]{"META-INF/spring/applicationContext-property.xml"});
    }

    //@Test
    public void testEditor() {
        Person person = (Person) ctx.getBean("person");
        System.out.printf("[%s,%s,%s]", person.getAddress().getStreet(), person.getAddress().getDoorNum(), person.getAddress().getPostCode());
    }

    @Test
    public void testSort() {

        SortedMap map = new TreeMap();

        // Add some elements:
        map.put("2", "Two");
        map.put("1", "One");
        map.put("5", "Five");
        map.put("4", "Four");
        map.put("3", "Three");

        // Display the lowest key:
        System.out.println("The lowest key value is: " + map.firstKey());

        // Display the highest key:
        System.out.println("The highest key value is: " + map.lastKey());

        // Display All key value
        System.out.println("All key value is:\n" + map);

        // Display the headMap:
        System.out.println("The head map is:\n" + map.headMap("4"));

        // Display the tailMap:
        System.out.println("The tail map is:\n" + map.tailMap("4"));

        // keySet method returns a Set view of the keys contained in this map.
        Iterator iterator = map.keySet().iterator();
        while (iterator.hasNext()) {
            Object key = iterator.next();
            System.out.println("key : " + key + " value :" + map.get(key));
        }
    }
}
