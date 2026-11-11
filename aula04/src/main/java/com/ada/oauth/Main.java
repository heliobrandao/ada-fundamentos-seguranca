package com.ada.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication(scanBasePackages = {"com.ada.oauth", "com.ada.jwt", "com.ada.criptografia"})
@Configuration("aula04Main")
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}
