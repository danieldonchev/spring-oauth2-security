package app;

import java.util.Optional;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class TestController {

    @GetMapping("hello-get")
    public Mono<ResponseEntity<String>> getHello() {

        return Mono.just(ResponseEntity.of(Optional.of("test")));
    }

  @GetMapping("hello-get2")
  public Mono<ResponseEntity<String>> getHello2() {

    return Mono.just(ResponseEntity.of(Optional.of("test-2")));
  }


}
