package com.ada.seguranca.aula07;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;

@SpringBootApplication
@Configuration("aula07Main")
public class Main {

    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}
