package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.services.RoleService;
import ru.kata.spring.boot_security.demo.services.UserService;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final UserService userService;
    private final RoleService roleService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public AdminController(UserService userService, RoleService roleService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @GetMapping()
    public String printUsers(ModelMap model, @AuthenticationPrincipal User thisUser) {
        var userSet = userService.findAllUsers();
        model.addAttribute("users", userSet);
        model.addAttribute("thisUser", thisUser);
        model.addAttribute("emptyUser", new User());
        List<String> allRoles = roleService.getAllRoles().stream().map(Role::toString).map(x -> x.replace("ROLE_", "")).collect(Collectors.toList());
        model.addAttribute("allRoles", allRoles);

        return "admin_panel";
    }

    @PostMapping("/new")
    public String createUser(@ModelAttribute("user") User user, @ModelAttribute("role") String role) {
        user.setRolesSet(
                roleService.getAllRoles().stream().anyMatch(r -> r.getName().equals(role)) ?
                        roleService.findByNameRole(role).toSet() :
                        roleService.findByNameRole("ROLE_USER").toSet());
        userService.saveOrUpdateUser(user);
        return "redirect:/admin";
    }

    @PostMapping("/edit/{id}")
    public String updateUser(@PathVariable Long id, @ModelAttribute User user, @RequestParam(value = "role") String role) {
        if (user != null) {
            user.setRolesSet(
                    roleService.getAllRoles().stream().anyMatch(r -> r.getName().equals(role)) ?
                            roleService.findByNameRole(role).toSet() :
                            roleService.findByNameRole("ROLE_USER").toSet());
            if (user.getPassword() == null || user.getPassword().isEmpty()) {
                user.setPassword(userService.findUserByID(id).getPassword());
            } else {
                user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
            }
            user.setId(id);
            userService.saveOrUpdateUser(user);
        }
        return "redirect:/admin";
    }

    @GetMapping("/delete/{id}")
    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }

}

