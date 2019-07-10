package app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.web.reactive.config.EnableWebFlux;

@PropertySource("classpath:application.properties")
@SpringBootApplication(scanBasePackages = "app")
@EnableWebFlux
@EnableReactiveMethodSecurity
public class Application {

    public static void main(String... args) {

        SpringApplication.run(Application.class, args);
    }
}
