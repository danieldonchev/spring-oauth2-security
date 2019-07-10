package app;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

@Component
public class Oauth2RequestRedirectWebFilter implements WebFilter {

  private final ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;

  @Autowired
  private AuthorizationRequestRepository authorizationRequestRepository;

  public Oauth2RequestRedirectWebFilter(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    this.authorizationRequestResolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
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
          .then(putRedirectUrlInBody(exchange, redirectUri));
    });
  }

  private Mono<Void> putRedirectUrlInBody(ServerWebExchange exchange, URI redirectUri) {

    String url = redirectUri.toString();

    exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);
    exchange.getResponse().setStatusCode(HttpStatus.OK);

    byte[] bytes = url.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

    return exchange.getResponse().writeWith(Mono.just(buffer));
  }
}
