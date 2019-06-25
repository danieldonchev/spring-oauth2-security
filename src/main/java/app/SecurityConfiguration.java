package app;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

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

  @Autowired
  private SecurityContextRepository contextRepository;

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
          .requestCache().requestCache(NoOpServerRequestCache.getInstance())
        .and()
          .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
          .authorizeExchange()
          .pathMatchers("/hello-get")
            .permitAll()
          .anyExchange()
            .authenticated()
        .and()
          .oauth2Client()
            .clientRegistrationRepository(clientRegistrationRepository)
        .and()
          .oauth2Login()
            .clientRegistrationRepository(clientRegistrationRepository)
        .and()
          .addFilterAt(authenticationWebFilter(), SecurityWebFiltersOrder.AUTHENTICATION)

//            .authenticationConverter(converter)
//            .authenticationManager(manager)
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
    NegatedServerWebExchangeMatcher negateWhiteList = new NegatedServerWebExchangeMatcher(
            ServerWebExchangeMatchers.pathMatchers("/login/oauth2/code/{registrationId}"));
    authenticationWebFilter.setRequiresAuthenticationMatcher(negateWhiteList);

    authenticationWebFilter.setAuthenticationSuccessHandler(new ServerAuthenticationSuccessHandler() {
      @Override
      public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {

        return Mono.empty();
      }
    });
    authenticationWebFilter
            .setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());
    authenticationWebFilter.setAuthenticationFailureHandler((webFilterExchange, exception) -> Mono.error(exception));
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
