package com.ada.seguranca.aula07;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    // Consulta derivada do Spring Data -> 100% parametrizada contra SQL Injection (Aula 06)
    Optional<Usuario> findByUsername(String username);
}
