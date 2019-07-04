package app;

import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class User implements OAuth2User {

  private String name;
  private String accessToken;

  public User() { }

  public User(String name, String accessToken) {
    this.name = name;
    this.accessToken = accessToken;
  }

  public String getAccessToken() {
    return accessToken;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }

  @Override
  public Map<String, Object> getAttributes() {
    return null;
  }

  @Override
  public String getName() {
    return null;
  }
}
