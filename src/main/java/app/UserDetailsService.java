package app;

import app.oauth2authorization.AuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
public class UserDetailsService implements ReactiveUserDetailsService {

  private AuthRepository authRepository;

  @Autowired
  public UserDetailsService(AuthRepository authRepository) {

    this.authRepository = authRepository;
  }

  @Override
  public Mono<UserDetails> findByUsername(String email) {
    return authRepository.findByEmail(email).cast(UserDetails.class);
  }
}
