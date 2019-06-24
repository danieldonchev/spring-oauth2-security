package app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@EnableWebFluxSecurity
public class SecurityConfiguration {

  @Autowired
  private AuthenticationManager manager;

  @Autowired
  private SecurityContextRepository securityContextRepository;

  @Autowired
  private ReactiveClientRegistrationRepository clientRegistrationRepository;

  @Autowired
  private ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService;

  @Autowired
  private ServerBearerTokenAuthenticationConverter converter;

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

    http
        .httpBasic().disable()
        .formLogin().disable()
        .authenticationManager(manager)
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .authorizeExchange()
        .pathMatchers("/hello-get")
        .permitAll()
        .anyExchange().authenticated()
        .and()
        .oauth2Client()
        .authenticationManager(manager)
        .and()
//        .addFilterAt(, SecurityWebFiltersOrder.AUTHENTICATION)
        .oauth2Login()
        .authorizedClientService(oAuth2AuthorizedClientService)
        .clientRegistrationRepository(clientRegistrationRepository)
        .authenticationConverter(converter)
        .and()
        .oauth2ResourceServer()
        .jwt()
        .authenticationManager(manager);
    return http.build();
  }

  @Bean
  public ServerBearerTokenAuthenticationConverter converter() {

    return new ServerBearerTokenAuthenticationConverter();
  }
}

//  private AuthenticationWebFilter authenticationWebFilter() {
//
//    AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(manager);
//    authenticationWebFilter.setServerAuthenticationConverter(new JwtAuthenticationConverter(tokenProvider));
//    NegatedServerWebExchangeMatcher negateWhiteList = new NegatedServerWebExchangeMatcher(
//        ServerWebExchangeMatchers.pathMatchers(AUTH_WHITELIST));
//    authenticationWebFilter.setRequiresAuthenticationMatcher(negateWhiteList);
//    authenticationWebFilter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
//    authenticationWebFilter.setAuthenticationFailureHandler(responseError());
//    return authenticationWebFilter;
//  }
//
//
//public class JwtAuthenticationConverter implements ServerAuthenticationConverter {
//  private final TokenProvider tokenProvider;
//
//  public JwtAuthenticationConverter(TokenProvider tokenProvider) {
//    this.tokenProvider = tokenProvider;
//  }
//
//  private Mono<String> resolveToken(ServerWebExchange exchange) {
////    log.debug("servletPath: {}", exchange.getRequest().getPath());
//    return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
//        .filter(t -> t.startsWith("Bearer "))
//        .map(t -> t.substring(7));
//  }
//
//  @Override
//  public Mono<Authentication> convert(ServerWebExchange exchange) {
//
//    return resolveToken(exchange)
//        .filter(tokenProvider::validateToken)
//        .map(tokenProvider::getAuthentication);
//  }
//
//}
