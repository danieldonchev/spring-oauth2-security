package app;

import java.net.URI;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

public class Oauth2RequestRedirectWebFilter implements WebFilter {

  private final ServerRedirectStrategy authorizationRedirectStrategy = new DefaultServerRedirectStrategy();
  private final ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
  private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
      new AuthRequestRepo();

  /**
   * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
   *
   * @param clientRegistrationRepository the repository of client registrations
   */
  public Oauth2RequestRedirectWebFilter(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    this.authorizationRequestResolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
  }

  /**
   * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
   *
   * @param authorizationRequestResolver the resolver to use
   */
  public Oauth2RequestRedirectWebFilter(ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver) {
    Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
    this.authorizationRequestResolver = authorizationRequestResolver;
  }

  /**
   * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
   *
   * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
   */
  public final void setAuthorizationRequestRepository(
      ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
    Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
    this.authorizationRequestRepository = authorizationRequestRepository;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return this.authorizationRequestResolver.resolve(exchange)
        .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
        .onErrorResume(ClientAuthorizationRequiredException.class, e -> this.authorizationRequestResolver.resolve(exchange, e.getClientRegistrationId()))
        .flatMap(clientRegistration -> sendRedirectForAuthorization(exchange, clientRegistration));
  }

  private Mono<Void> sendRedirectForAuthorization(ServerWebExchange exchange,
      OAuth2AuthorizationRequest authorizationRequest) {
    return Mono.defer(() -> {
      Mono<Void> saveAuthorizationRequest = Mono.empty();
      if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
        saveAuthorizationRequest = this.authorizationRequestRepository
            .saveAuthorizationRequest(authorizationRequest, exchange);
      }

      URI redirectUri = UriComponentsBuilder
          .fromUriString(authorizationRequest.getAuthorizationRequestUri())
          .build(true).toUri();
      return saveAuthorizationRequest
          .then(this.authorizationRedirectStrategy.sendRedirect(exchange, redirectUri));
    });
  }
}
