package app;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Mono;

public class Oauth2RequestRedirectWebFilter implements WebFilter {

  private final ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
  private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
      new AuthorizationRequestRepository();


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
      try {
		return saveAuthorizationRequest
		      .then(putRedirectUrlInBody(exchange, redirectUri));
	} catch (JsonProcessingException e) {
		// TODO Auto-generated catch block
		throw new RuntimeException();
	}
    });
  }

  private Mono<Void> putRedirectUrlInBody(ServerWebExchange exchange, URI redirectUri) throws JsonProcessingException {

    String url = redirectUri.toString();

    exchange.getResponse().setStatusCode(HttpStatus.OK);
    
    exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin", "*");
    exchange.getResponse().getHeaders().add("Content-Type", "application/json");
    exchange.getResponse().getHeaders().add("Access-Control-Allow-Headers", "*");
    
    ObjectMapper objectMapper = new ObjectMapper();
    
    FacebookRedirectUrlModel redirectUrl = new FacebookRedirectUrlModel();
    
    redirectUrl.setRedirectUrl(url);
    
    String newUrl = objectMapper.writeValueAsString(redirectUrl);
    
    byte[] bytes = newUrl.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

    return exchange.getResponse().writeWith(Mono.just(buffer));
  }
}
