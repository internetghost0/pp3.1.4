package ru.kata.spring.boot_security.demo.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.services.RoleService;
import ru.kata.spring.boot_security.demo.services.UserService;

import javax.annotation.PostConstruct;

@Component
public class Init {

    @Autowired
    private UserService userService;
    @Autowired
    private RoleService roleService;

    @PostConstruct
    public void postConstruct() {
        roleService.saveOrUpdateRole(new Role("ROLE_ADMIN"));
        roleService.saveOrUpdateRole(new Role("ROLE_USER"));

        User adminUser = new User("admin@mail.ru", "admin", "admin", "admin", 35, roleService.getAllRoles());
        userService.saveOrUpdateUser(adminUser);

        User adminUser2 = new User("1@", "1", "1", "1", 1, roleService.getAllRoles());
        userService.saveOrUpdateUser(adminUser2);

        User user = new User("user@mail.ru", "user", "user", "user", 35, roleService.findByNameRole("ROLE_USER").toSet());
        userService.saveOrUpdateUser(user);


    }
}
