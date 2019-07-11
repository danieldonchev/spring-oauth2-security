package app;

import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

//TODO : Fix principal fields
public class UserPrincipal implements OAuth2User {

  private String id;
  private String email;
  private String name;
  private String accessToken;

  public UserPrincipal() { }

  public UserPrincipal(String id, String email, String name, String accessToken) {
    this.id = id;
    this.email = email;
    this.name = name;
    this.accessToken = accessToken;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getAccessToken() {
    return accessToken;
  }

  public void setAccessToken(String accessToken) {
    this.accessToken = accessToken;
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
    return this.name;
  }
}
