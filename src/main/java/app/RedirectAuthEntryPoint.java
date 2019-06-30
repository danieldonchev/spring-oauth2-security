package app;

import java.net.URI;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class RedirectAuthEntryPoint implements ServerAuthenticationEntryPoint {

  private final URI location;

  private ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

  /**
   * Creates an instance
   * @param location the location to redirect to (i.e. "/logout-success")
   */
  public RedirectAuthEntryPoint(String location) {
    Assert.notNull(location, "location cannot be null");
    this.location = URI.create(location);
  }

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
    return this.redirectStrategy.sendRedirect(exchange, this.location);
  }

  /**
   * Sets the RedirectStrategy to use.
   * @param redirectStrategy the strategy to use. Default is DefaultRedirectStrategy.
   */
  public void setRedirectStrategy(ServerRedirectStrategy redirectStrategy) {
    Assert.notNull(redirectStrategy, "redirectStrategy cannot be null");
    this.redirectStrategy = redirectStrategy;
  }
}
