package com.test4.test4;

//import com.test4.test4.services.UserDataService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
public class Test4Application {

	public static void main(String[] args) {
		//ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext("ApplicationConfig.xml");
		SpringApplication.run(Test4Application.class, args);

//		UserRepository userRepository =context.getBean(UserRepository.class);
//
//		//UserDataService userDataService = new UserDataService( );




	}

}
