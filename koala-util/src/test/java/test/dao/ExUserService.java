package test.dao;

import org.koala.dao.IGenericDao;
import test.model.ExUser;

public interface ExUserService extends IGenericDao<ExUser, Integer> {

    public int service(String username);
}
