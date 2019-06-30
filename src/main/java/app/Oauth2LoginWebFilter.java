package app;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationCodeAuthenticationTokenConverter;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import reactor.core.publisher.Mono;

public class Oauth2LoginWebFilter extends AuthenticationWebFilter {

  public Oauth2LoginWebFilter(
      ReactiveAuthenticationManager authenticationManager,
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    super(authenticationManager);

    setRequiresAuthenticationMatcher(createAttemptAuthenticationRequestMatcher());
    setServerAuthenticationConverter(new AuthCodeTokenConverter(
        clientRegistrationRepository));
    setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());

    setAuthenticationSuccessHandler((webFilterExchange, authentication) -> Mono.empty());
    setAuthenticationFailureHandler((webFilterExchange, exception) -> Mono.error(exception));
  }

  @Override
  protected Mono<Void> onAuthenticationSuccess(Authentication authentication,
      WebFilterExchange webFilterExchange) {
    OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) authentication;

    OAuth2AuthenticationToken result = new OAuth2AuthenticationToken(
        authenticationResult.getPrincipal(),
        authenticationResult.getAuthorities(),
        authenticationResult.getClientRegistration().getRegistrationId());
    return super.onAuthenticationSuccess(result, webFilterExchange);
  }

  private ServerWebExchangeMatcher createAttemptAuthenticationRequestMatcher() {
    PathPatternParserServerWebExchangeMatcher loginPathMatcher = new PathPatternParserServerWebExchangeMatcher(
        "/login/oauth2/code/{registrationId}");
    ServerWebExchangeMatcher notAuthenticatedMatcher = e -> ReactiveSecurityContextHolder
        .getContext()
        .flatMap(p -> ServerWebExchangeMatcher.MatchResult.notMatch())
        .switchIfEmpty(ServerWebExchangeMatcher.MatchResult.match());
    return new AndServerWebExchangeMatcher(loginPathMatcher, notAuthenticatedMatcher);
  }
}