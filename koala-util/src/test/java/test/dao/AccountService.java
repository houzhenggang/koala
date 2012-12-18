package test.dao;

import org.koala.dao.IGenericDao;
import test.model.Account;

public interface AccountService extends IGenericDao<Account, Long> {
	public String service(String name);
}
