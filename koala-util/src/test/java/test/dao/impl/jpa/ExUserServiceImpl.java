package test.dao.impl.jpa;

import org.koala.dao.jpa.GenericJPADao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import test.dao.ExUserService;
import test.model.ExUser;

@Component("exuserservice")
@Transactional
public class ExUserServiceImpl extends GenericJPADao<ExUser, Integer> implements
        ExUserService {

    public static final Logger logger = LoggerFactory.getLogger(ExUserServiceImpl.class);

    @Override
    public int service(final String username) {
        ExUser eu = findSingle("find.test.eu", new String[]{"username"},
                new Object[]{username});
        logger.info("@@:{},{}", eu.getId(), eu.getUserDetail().getId());
        return eu.getId();
    }
}
