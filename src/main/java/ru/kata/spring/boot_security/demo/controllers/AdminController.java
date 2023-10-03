package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.services.RoleService;
import ru.kata.spring.boot_security.demo.services.UserService;

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
        return "admin_panel";
    }

    @GetMapping("/new")
    @ResponseBody
    public String createUserForm(Model model) {
        model.addAttribute("user", new User());
        return "TODO";
    }

    @PostMapping("/new")
    public String createUser(@ModelAttribute("user") User user, @ModelAttribute("role") String role) {
        user.setRolesSet(
                roleService.getAllRoles().stream().anyMatch(r -> r.getEmail().equals(role)) ?
                        roleService.findByNameRole(role).toSet() :
                        roleService.findByNameRole("ROLE_USER").toSet());
        userService.saveOrUpdateUser(user);
        return "redirect:/admin";
    }

    // Edit user form
    @GetMapping("/edit/{id}")
    @ResponseBody
    public String editUserForm(@PathVariable Long id, Model model) {
        User user = userService.findUserByID(id);
        model.addAttribute("user", user);
        model.addAttribute("id", id);
        return "TODO";
    }

    @PostMapping("/edit/{id}")
    public String updateUser(@PathVariable Long id, @ModelAttribute User user, @RequestParam(value = "role") String role) {
        if (user != null) {
            user.setRolesSet(
                    roleService.getAllRoles().stream().anyMatch(r -> r.getEmail().equals(role)) ?
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

