package app.oauth2authorization;

import app.UserTest;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.r2dbc.repository.query.Query;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AuthRepository extends R2dbcRepository<UserTest, String> {

    @Query("SELECT * FROM UserTest WHERE email = $1")
    Mono<UserTest> findByEmail(String email);

    /**
     * // TODO : Implement transactions
     * Code used for transactions
     *
     *     UserRepository userRepository = …
     *     TransactionalDatabaseClient transactionalDatabaseClient = …
     *
     *         transactionalDatabaseClient.inTransaction(db -> {
     *         return userRepository.save(…).then(userRepository.count());
     *     });
     */

}

