package app;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;

@Configuration
public class OauthProviderConfiguration {

  private static String CLIENT_PROPERTY_KEY
      = "spring.security.oauth2.client.registration.";

  private static List<String> clients = Arrays.asList("google", "facebook");

  @Autowired
  private Environment env;

  @Bean
  public ReactiveClientRegistrationRepository clientRegistrationRepository() {
    List<ClientRegistration> registrations = clients.stream()
        .map(this::getRegistration)
        .filter(Objects::nonNull)
        .collect(Collectors.toList());

    return new InMemoryReactiveClientRegistrationRepository(registrations);
  }

  @Bean
  public ReactiveOAuth2AuthorizedClientService authorizedClientService() {

    return new InMemoryReactiveOAuth2AuthorizedClientService(
        clientRegistrationRepository());
  }

  private ClientRegistration getRegistration(String client) {
    String clientId = env.getProperty(
        CLIENT_PROPERTY_KEY + client + ".client-id");

    if (clientId == null) {
      return null;
    }

    String clientSecret = env.getProperty(
        CLIENT_PROPERTY_KEY + client + ".client-secret");

    if (client.equals("google")) {
      return CommonOAuth2Provider.GOOGLE.getBuilder(client)
          .clientId(clientId).clientSecret(clientSecret).build();
    }
    if (client.equals("facebook")) {
      return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
          .clientId(clientId).clientSecret(clientSecret).build();
    }
    return null;
  }

}
