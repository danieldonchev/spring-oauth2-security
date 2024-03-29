package app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfiguration {

  @Autowired
  private Oauth2LoginAuthenticationManager oauth2LoginAuthenticationManager;

  @Autowired
  private ReactiveClientRegistrationRepository clientRegistrationRepository;

  @Autowired
  private ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService;

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

    http
        .httpBasic()
        .disable()
        .formLogin()
        .disable()
        .csrf()
        .disable()
        .logout()
        .disable()
        .authenticationManager(oauth2LoginAuthenticationManager)
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .exceptionHandling()
        .authenticationEntryPoint(new AuthenticationEntryPoint())
        .accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(HttpStatus.BAD_REQUEST))
        .and()
        .requestCache().disable()
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .authorizeExchange()
        .pathMatchers("/login", "/hello-get")
        .permitAll()
        .anyExchange()
        .authenticated()
        .and()
        .addFilterAt(new Oauth2RequestRedirectWebFilter(clientRegistrationRepository), SecurityWebFiltersOrder.HTTP_BASIC)
        .addFilterAt(new OAuth2AuthenticationWebFilter(oauth2LoginAuthenticationManager,
            clientRegistrationRepository), SecurityWebFiltersOrder.AUTHENTICATION)
        .oauth2Login()
        .clientRegistrationRepository(clientRegistrationRepository)
        .authorizedClientRepository(clientRepository());
    return http.build();
  }

  private ServerOAuth2AuthorizedClientRepository clientRepository() {

    return new ServerOAuth2AuthorizedClientRepository() {
      @Override
      public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(
          String clientRegistrationId, Authentication principal,
          ServerWebExchange exchange) {
        return Mono.empty();
      }

      @Override
      public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient,
          Authentication principal, ServerWebExchange exchange) {
        return Mono.empty();
      }

      @Override
      public Mono<Void> removeAuthorizedClient(String clientRegistrationId,
          Authentication principal, ServerWebExchange exchange) {
        return Mono.empty();
      }
    };
  }
}

