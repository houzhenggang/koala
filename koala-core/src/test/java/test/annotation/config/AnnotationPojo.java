package test.annotation.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service("annonationPojo")
public class AnnotationPojo {

	@Autowired
	private DataSource dataSource;

	@Autowired
	@Qualifier("englishman")
	private IMan man;

	public void action() {
		System.out.println("[dataSource]" + this.dataSource);
		this.man.sayHello();
	}
}
