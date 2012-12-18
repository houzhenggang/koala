package test.annotation.aop;

import org.springframework.stereotype.Service;

@Service("helloworldaop")
public class HelloWorld {

	public void sayHello(String name) {
		System.out.printf("say hello world, [%s]\n", name);
	}

	public void sayBefore(String name, Integer age) {
		System.out.printf("say before, [%s,%d]\n", name, age);
	}

	public void sayAfter(String name, Integer age) {
		System.out.printf("say after, [%s,%d]\n", name, age);
	}
}
