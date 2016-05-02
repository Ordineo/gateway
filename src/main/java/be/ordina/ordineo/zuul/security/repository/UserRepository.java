package be.ordina.ordineo.zuul.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import be.ordina.ordineo.zuul.security.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
