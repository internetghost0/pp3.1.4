package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class BaseController {

    @GetMapping()
    public String index() {
        return "login";
    }

    @GetMapping("/login")
    public String redirect() {
        return "login";
    }

}

