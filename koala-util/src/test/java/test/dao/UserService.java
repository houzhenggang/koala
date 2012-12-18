package test.dao;

import org.koala.dao.IGenericDao;
import test.model.User;

public interface UserService extends IGenericDao<User, Integer>{
    public int service(String username);
}
