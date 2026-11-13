package com.ada.seguranca.aula07;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Entidade JPA de usuário.
 * ATENÇÃO: "user" é palavra reservada no SQL (inclusive no H2 e PostgreSQL),
 * por isso usamos @Table(name = "users").
 */
@Entity
@Table(name = "users")
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    // Guarda SEMPRE o hash BCrypt (ex.: $2a$10$...), NUNCA a senha em texto puro!
    @Column(nullable = false)
    private String password;

    protected Usuario() {
    }

    public Usuario(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
