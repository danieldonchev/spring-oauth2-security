package app;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationRequestRepository implements
    ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  public static final Map<String, OAuth2AuthorizationRequest> requests = new HashMap<>();

  @Autowired
  private RedisTemplate<String, OAuth2AuthorizationRequest> redisTemplate;

  @Override
  public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {

    return Mono.justOrEmpty(redisTemplate.opsForValue().get(getStateParameter(exchange)));
  }

  @Override
  public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
      ServerWebExchange exchange) {

    redisTemplate.opsForValue().set(authorizationRequest.getState(), authorizationRequest);
//    requests.put(authorizationRequest.getState(), authorizationRequest);
    return Mono.empty();
  }

  @Override
  public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {

    String state = getStateParameter(exchange);

    OAuth2AuthorizationRequest request = redisTemplate.opsForValue().get(state);
    redisTemplate.delete(state);
    return
        Mono.justOrEmpty(request);
  }

  private String getStateParameter(ServerWebExchange exchange) {
    Assert.notNull(exchange, "exchange cannot be null");
    return exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
  }
}
