package ru.kata.spring.boot_security.demo.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.models.User;

import java.util.Set;


public interface UserService extends UserDetailsService {
    boolean saveOrUpdateUser(User user);

    boolean deleteUser(Long id);

    User findUserByID(Long id);

    Set<User> findAllUsers();

    User findByUsername(String login);

}
