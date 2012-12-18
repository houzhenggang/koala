package test.annotation.config;

import org.springframework.stereotype.Service;

@Service("englishman")
public class EnglishMan implements IMan {

	public void sayHello() {
		System.out.println("This is American.");
	}

}
