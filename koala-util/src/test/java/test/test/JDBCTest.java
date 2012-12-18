package test.test;

import org.junit.Test;
import org.koala.dao.jdbc.IJDBCDao;
import org.springframework.context.support.AbstractApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.MessageSource;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.BeansException;
import test.dao.AccountJdbcService;
import test.dao.impl.jdbc.AccountJDBCDaoImpl;
import test.model.Account;
import test.model.Bill;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.ResourceBundle;

/**
 * @author liyafeng 这是JPA的测试程序！
 */
public class JDBCTest {

    private ApplicationContext actx = null;
    private AbstractApplicationContext ctx = null;
    private AccountJdbcService adao = null;

    public JDBCTest() {
        ctx = new ClassPathXmlApplicationContext(new String[]{
                    "META-INF/spring/applicationContext-common.xml", "META-INF/spring/applicationContext-jdbc.xml"});
        ctx.getBeanFactory().addBeanPostProcessor(new BeanPostProcessor() {

            public Object postProcessAfterInitialization(Object o, String s) throws BeansException {
                System.out.printf("[-------after------][%s,%s]\n", o.toString(), s);
                return o;
            }

            public Object postProcessBeforeInitialization(Object o, String s) throws BeansException {
                System.out.printf("[-------before------][%s,%s]\n", o.toString(), s);
                return o;
            }
        });
        System.out.printf("[----messageSource---][%s]\n", ((MessageSource) ctx).getMessage("tsql", null, null));
        adao = (AccountJdbcService) ctx.getBean(AccountJDBCDaoImpl.class.getName());
    }

    public void destory() {
        if (ctx != null) {
            ctx.registerShutdownHook();
        }
    }

    @Test
    public void add() {
        ResourceBundle rb = ResourceBundle.getBundle("sql");
        System.out.printf("[classname][%s]\n", adao.getClass().getName());
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < 5; i++) {
            buffer.append("****************");
        }
        System.out.println(buffer.toString());
        String sql = rb.getString("sql");
        String insql = rb.getString("insql");
        String ssql = rb.getString("ssql");
        String tsql = rb.getString("tsql");

        Account acc = new Account();
        Long aid = System.currentTimeMillis();
        acc.setAid(aid);
        acc.setAdddesc("JDBCAdddesc");
        acc.setAddress("JDBCaddress");
        acc.setAname("JDBCName");
        acc.setAdesc("JDBCDesc");
        adao.save(insql, acc);
        List<Account> la = adao.find(sql, 2, 4);
        for (Account aca : la) {
            System.out.printf("[aid,aname][%d,%s]\n", aca.getAid(), aca.getAname());
        }
        /*
        Account sacc = adao.findForObject(ssql, aid);
        Account tacc = new Account();
        tacc.setAid(aid);
        tacc = adao.findForObject(tsql, tacc);
        System.out.println(buffer.toString());
        System.out.printf("[aid,aname,address,adec,adddesc][%d,%s,%s,%s,%s]\n", sacc.getAid(),
        sacc.getAname(), sacc.getAddress(), sacc.getAdesc(), sacc.getAdddesc());
        System.out.println(buffer.toString());
        System.out.printf("[aid,aname,address,adec,adddesc][%d,%s,%s,%s,%s]\n", tacc.getAid(),
        tacc.getAname(), tacc.getAddress(), tacc.getAdesc(), tacc.getAdddesc());
         */
    }

//    @Test
    public void newtest() {
        try {
            Calendar cal = Calendar.getInstance();
            DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            IJDBCDao dao = (IJDBCDao) ctx.getBean("baseJDBCDao");

            cal.setTimeInMillis(System.currentTimeMillis());
            System.out.println(df.format(cal.getTime()));
            for (int i = 0; i < 20; i++) {
                List<Bill> items = dao.find("select RID as rid,RCREATEDATE as rcreatedate,USERNAME as username from HT_BILL", Bill.class);
                /*
                for (Bill item : items) {
                System.out.printf("[%s,%s,%s]\n", item.getRid(), item.getUsername(), item.getRcreatedate());
                }
                 */
            }
            cal.setTimeInMillis(System.currentTimeMillis());
            System.out.println(df.format(cal.getTime()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
