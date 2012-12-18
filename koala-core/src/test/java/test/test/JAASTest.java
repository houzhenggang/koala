package test.test;

import org.junit.Test;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import java.io.File;
import java.security.PrivilegedAction;

/**
 * User: phoenixup
 * Date: 11-5-17
 * Time: 上午8:21
 */
public class JAASTest {
	public JAASTest(){
		System.out.println("user.dir="+System.getProperty("user.dir"));
//		System.setProperty("java.security.auth.login.config",new File(System.getProperty("user.dir"),"src/test/resources/jaas.config").getAbsolutePath());
		System.out.println("java.security.auth.login.config="+System.getProperty("java.security.auth.login.config"));

	}
	@Test
	public void testJaas() {

		LoginContext lc = null;
		try {
			lc = new LoginContext("myExample");
			lc.login();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (lc != null) {
			Subject sub = lc.getSubject();
			Subject.doAs(sub, new MyPrivateAction());
		}
	}

	class MyPrivateAction implements PrivilegedAction {
		@Override
		public Object run() {
			System.out.printf("#######################\n%s\n#######################\n", "What the fuck!");
			return "Hello World!";
		}
	}
}
