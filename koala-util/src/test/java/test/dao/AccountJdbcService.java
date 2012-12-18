package test.dao;

import org.koala.dao.jdbc.IGenericJDBCDao;
import test.model.Account;

public interface AccountJdbcService extends IGenericJDBCDao<Account, Long> {
}
