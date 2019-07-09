package app;

import java.nio.charset.StandardCharsets;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class AuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

  public AuthenticationEntryPoint() {
  }

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {

    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

    String unauthorizedMessage = "The request is not authorized.";
    byte[] bytes = unauthorizedMessage.getBytes(StandardCharsets.UTF_8);
    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

    return exchange.getResponse().writeWith(Mono.just(buffer));
  }
}
