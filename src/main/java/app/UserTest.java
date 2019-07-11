package app;

import org.springframework.data.annotation.Id;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

// TODO : Fix UserTest fields

@Table("usertest")
public class UserTest implements Persistable<String> {

  @Id
  private String id;
  private String email;
  private String name;

  public UserTest() {
  }

  public UserTest(String id, String email, String name) {
    this.id = id;
    this.email = email;
    this.name = name;
  }

  /**
      TODO : create persist by id strategy or use @GeneratedValue annotation.
      {@link PersistentEntityInformation#isNew()}
   */
  @Override
  public boolean isNew() {
    return true;
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

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }
}
