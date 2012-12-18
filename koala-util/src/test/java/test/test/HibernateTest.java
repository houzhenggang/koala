package test.test;

import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import test.dao.AccountService;
import test.dao.impl.hibernate.AccountHBNServiceImpl;
import test.model.Account;

public class HibernateTest {

    private ApplicationContext ctx = null;
    private AccountService hadao = null;

    public HibernateTest() {
        ctx = new ClassPathXmlApplicationContext(new String[]{
                    "META-INF/spring/applicationContext-common.xml",
                    "META-INF/spring/applicationContext-hibernate.xml"});
        hadao = (AccountService) ctx.getBean(AccountHBNServiceImpl.beanName,
                AccountService.class);
    }

    @Test
    public void save() {
        Account account = new Account();
        account.setAname("hibernate2");
        account.setAdesc("hibernate2-desc");
        account.setAddress("beijing");
        hadao.save(account);
    }

    @Test
    public void find() {
        for (Account item : hadao.find("find.all")) {
            System.out.println("[find()]" + item.getAid() + "|" + item.getAdesc());
        }
        for (Account acc : hadao.findAll()) {
            System.out.println("[find()]" + acc.getAid() + "|" + acc.getAdesc());
        }
        for (Account acc : hadao.find("find.all", 2, 5)) {
            System.out.println("[find(2,5)]" + acc.getAid() + "|" + acc.getAdesc());
        }
        for (Account acc : hadao.find("find.all", 2, 6)) {
            System.out.println("[find(2,6)]" + acc.getAid() + "|" + acc.getAdesc());
        }
        System.out.println(hadao.find("find.count.all"));
    }
}
