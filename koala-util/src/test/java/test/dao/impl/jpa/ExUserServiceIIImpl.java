package test.dao.impl.jpa;

import java.util.Date;
import org.koala.dao.IDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import test.dao.ExUserServiceII;
import test.model.ExUser;
import test.model.UserDetail;

/**
 *
 * @author phoenixup
 */
@Service("ExUserServiceII")
@Transactional
public class ExUserServiceIIImpl implements ExUserServiceII {

    @Autowired
    @Qualifier("baseJPADao")
    private IDao dao;

    public IDao getDao() {
        return dao;
    }

    public void setDao(IDao dao) {
        this.dao = dao;
    }


    @Override
    public int service(String username) {
        UserDetail ud = new UserDetail();
        ud.setAddress("nanjing");
        ud.setBirthday(new Date());
        ud.setUsername(username);
        dao.save(ud);
        ExUser user = new ExUser();
        user.setUsername(username);
        user.setAge("12");
        user.setExkey("exkey_1");
        user.setPassword("123456");
        user.setUserDetail(ud);
        dao.save(user);
        return user.getId();
    }
}
