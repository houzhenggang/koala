package test.annotation.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.After;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Service;

@Service("aopdeal")
@Aspect
public class AopDeal {

	@Around("execution(* test.annotation.aop.HelloWorld.sayHello(*))")
	public Object aroundSay(ProceedingJoinPoint pjp) throws Throwable {
		System.out.println("****************************");
		System.out.println("[AOP]Around ONE!");
		for (Object ob : pjp.getArgs()) {
			System.out.println("[around]" + ob.toString());
		}
		System.out.println("****************************");
		Object obj = pjp.proceed();
		System.out.println("****************************");
		System.out.println("[AOP]Around TWO!");
		System.out.println("****************************");
		return obj;
	}

	@Before("execution(* test.annotation.aop.HelloWorld.sayBefore(*,*))")
	public void beforeSay() {
		System.out.println("****************************");
		System.out.println("[AOP]Before!");
		System.out.println("****************************");
	}

	@After("execution(* test.annotation.aop.HelloWorld.sayAfter(*,*))")
	public void afterSay() {
		System.out.println("****************************");
		System.out.println("[AOP]After!");
		System.out.println("****************************");
	}
}
