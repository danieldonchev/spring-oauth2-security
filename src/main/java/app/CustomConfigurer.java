package app;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;

@Configuration
public class CustomConfigurer implements WebFluxConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
      registry.addMapping("/**").allowedOrigins("*").allowedMethods("*").allowedHeaders("*");
    }
  }
