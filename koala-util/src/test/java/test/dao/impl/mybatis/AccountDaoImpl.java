package test.dao.impl.mybatis;

import java.util.List;
import org.koala.dao.mybatis.BaseMyBatisDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import test.dao.AccountMyBatisService;
import test.model.Account;

@Service("AccountMyBatisService")
@Transactional
public class AccountDaoImpl implements AccountMyBatisService {

    public static final Logger logger = LoggerFactory.getLogger(AccountDaoImpl.class);
    @Autowired
    private BaseMyBatisDao dao;

    public void setDao(BaseMyBatisDao dao) {
        this.dao = dao;
    }

    public void service(String name) {
        Long aid = System.currentTimeMillis();
        Account acc = new Account();
        acc.setAid(aid);
        acc.setAname("Hello");
        acc.setAddress("nanjing");
        acc.setAdesc("nanjing jiangsu zhongguo");
        acc.setAdddesc("What the fuck!");
        dao.getSqlSession().insert("test.model.Account.saveone", acc);
        Object obj = dao.getSqlSession().selectOne("test.model.Account.findone", aid);
        logger.error("$:{}", obj);
        List<Account> accs = (List<Account>) dao.getSqlSession().selectList("test.model.Account.findall");
        logger.error("$:{}", accs);
    }
}
