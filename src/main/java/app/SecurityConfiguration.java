package app;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfiguration {

  @Autowired
  private AuthenticationManager manager;

  @Autowired
  private ReactiveClientRegistrationRepository clientRegistrationRepository;

  @Autowired
  private ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService;

  @Autowired
  private JwtAuthenticationConverter converter;

//  @Autowired
//  private ServerBearerTokenAuthenticationConverter converter;

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
//          .authenticationManager(manager)
          .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
          .authorizeExchange()
          .pathMatchers("/hello-get")
            .permitAll()
          .anyExchange()
            .authenticated()
//        .and()
//          .oauth2Client()
//          .authenticationConverter(converter)
//          .authenticationManager(manager)
        .and()
//          .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
          .oauth2Login()
            .clientRegistrationRepository(clientRegistrationRepository)
            .authenticationConverter(converter)
            .authenticationManager(manager)
            .authorizedClientService()
//        .and()
//          .oauth2ResourceServer()
//            .jwt()
//            .authenticationManager(manager)
    ;
    return http.build();
  }

//
//    @Bean
//    public MapReactiveUserDetailsService userDetailsService() {
//         UserDetails user = User.withUsername("user")
//              .username("user")
//              .password("password")
//              .roles("USER")
//              .build();
//         return new MapReactiveUserDetailsService(user);
//    }

//  @Bean
//  public ServerBearerTokenAuthenticationConverter converter() {
//
//    return new ServerBearerTokenAuthenticationConverter();
//  }

  private AuthenticationWebFilter authenticationWebFilter() {

    AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(manager);
    authenticationWebFilter
        .setServerAuthenticationConverter(new JwtAuthenticationConverter());
//    NegatedServerWebExchangeMatcher negateWhiteList = new NegatedServerWebExchangeMatcher(
//        ServerWebExchangeMatchers.pathMatchers(AUTH_WHITELIST));
//    authenticationWebFilter.setRequiresAuthenticationMatcher(negateWhiteList);
    authenticationWebFilter
        .setSecurityContextRepository(new WebSessionServerSecurityContextRepository());
//    authenticationWebFilter.setAuthenticationFailureHandler();
    return authenticationWebFilter;
  }

//  public String createToken(Authentication authentication, boolean rememberMe) {
//    String authorities = authentication.getAuthorities().stream()
//        .map(GrantedAuthority::getAuthority)
//        .collect(Collectors.joining(","));
//
//    long now = (new Date()).getTime();
//    Date validity;
//    if (rememberMe) {
//      validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
//    } else {
//      validity = new Date(now + this.tokenValidityInMilliseconds);
//    }
//
//    return Jwts.builder()
//        .setSubject(authentication.getName())
//        .claim(AUTHORITIES_KEY, authorities)
//        .signWith(key, SignatureAlgorithm.HS512)
//        .setExpiration(validity)
//        .compact();
//  }

}

//
//}
