package app.oauth2authorization;

import app.User;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.r2dbc.repository.query.Query;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthRepository extends R2dbcRepository<User, Long> {

    @Query("SELECT * FROM user WHERE email = $1")
    Mono<User> findByEmail(String email);
}

