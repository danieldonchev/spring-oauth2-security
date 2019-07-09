package app;

import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class AuthorizationRequestRepository implements
    ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  public static final Map<String, OAuth2AuthorizationRequest> requests = new HashMap<>();

  @Override
  public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {

    return Mono.justOrEmpty(requests.get(getStateParameter(exchange)));
  }

  @Override
  public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
      ServerWebExchange exchange) {

    requests.put(authorizationRequest.getState(), authorizationRequest);
    return Mono.empty();
  }

  @Override
  public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
    return
        Mono.justOrEmpty(requests.remove(getStateParameter(exchange)));
  }

  private String getStateParameter(ServerWebExchange exchange) {
    Assert.notNull(exchange, "exchange cannot be null");
    return exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
  }
}
