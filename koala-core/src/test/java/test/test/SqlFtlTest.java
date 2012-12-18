package test.test;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.junit.Before;
import org.junit.Test;
import org.koala.spring.support.SqlFtlUtils;

import java.util.Map;
import java.util.HashMap;
import java.util.ResourceBundle;

/**
 * Created by YaFengli.
 * User: YaFengLi
 * Date: 2009-5-12
 * Time: 10:36:11
 */
public class SqlFtlTest {

    ApplicationContext ctx = null;

    @Before
    public void init() {
        ctx = new ClassPathXmlApplicationContext(new String[]{"META-INF/spring/applicationContext-sql.xml"});
    }

    @Test
    public void testSql() {
        SqlFtlUtils sfu = (SqlFtlUtils) ctx.getBean("sqlftlutil");
        Map map = new HashMap();
        Map hello = new HashMap();
        hello.put("startdate", "#2011-05-10 12:09:03#");
        hello.put("enddate", "#2132-05-10 12:09:03#");
        hello.put("areacode", "#nanjing#");
        map.put("item", hello);
        try {
            String key = "find.one";
            long startl = System.currentTimeMillis();
            for (int i = 0; i < 50000; i++) {
                sfu.process(key, ResourceBundle.getBundle("sql"), map);
            }
            long endl = System.currentTimeMillis();
            System.out.printf("[start,end,delay][%s,%s,%s]\n", startl, endl, (endl - startl) / 1000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
