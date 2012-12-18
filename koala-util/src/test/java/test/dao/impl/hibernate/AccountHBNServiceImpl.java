package test.dao.impl.hibernate;

import org.koala.dao.hibernate.GenericHibernateDao;
import org.springframework.transaction.annotation.Transactional;

import test.dao.AccountService;
import test.model.Account;

@Transactional
public class AccountHBNServiceImpl extends GenericHibernateDao<Account, Long> implements AccountService {

    public static final String beanName = "haccountDao";

	@Override
	public String service(String name) {
		// TODO Auto-generated method stub
		return null;
	}
    
}
