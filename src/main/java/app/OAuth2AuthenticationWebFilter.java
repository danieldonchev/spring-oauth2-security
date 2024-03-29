package app;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.AndServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import reactor.core.publisher.Mono;

public class OAuth2AuthenticationWebFilter extends AuthenticationWebFilter {

  public OAuth2AuthenticationWebFilter(
      ReactiveAuthenticationManager authenticationManager,
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    super(authenticationManager);

    setRequiresAuthenticationMatcher(createAttemptAuthenticationRequestMatcher());
    setServerAuthenticationConverter(new AuthorizationCodeTokenConverter(
        clientRegistrationRepository));
    setSecurityContextRepository(NoOpServerSecurityContextRepository.getInstance());

    setAuthenticationSuccessHandler((webFilterExchange, authentication) -> {

      // add access token to header

      webFilterExchange.getExchange().getResponse().getHeaders()
          .add("access_token", "test_access_token");

      ObjectMapper om = new ObjectMapper();
      String result;
      try {
        result = om.writeValueAsString(authentication);
      } catch (JsonProcessingException e) {
        result = "Something went wrong in authentication";
        webFilterExchange.getExchange().getResponse()
            .setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
      }
      byte[] bytes = result.getBytes(StandardCharsets.UTF_8);
      DataBuffer buffer = webFilterExchange.getExchange().getResponse().bufferFactory().wrap(bytes);

      webFilterExchange.getExchange().getResponse().getHeaders().add("Access-Control-Allow-Origin", "*");
      webFilterExchange.getExchange().getResponse().getHeaders().add("Content-Type", "application/json");
      webFilterExchange.getExchange().getResponse().getHeaders().add("Access-Control-Allow-Headers", "*");
      
      return webFilterExchange.getExchange().getResponse().writeWith(Mono.just(buffer));
    });
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
