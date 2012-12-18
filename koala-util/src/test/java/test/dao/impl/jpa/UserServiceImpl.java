package test.dao.impl.jpa;


import org.koala.dao.jpa.GenericJPADao;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import test.dao.UserService;
import test.model.User;

@Component("userservice")
@Transactional
public class UserServiceImpl extends GenericJPADao<User, Integer> implements
        UserService {

    @Override
    public int service(String username) {
        return 1;
    }
}
