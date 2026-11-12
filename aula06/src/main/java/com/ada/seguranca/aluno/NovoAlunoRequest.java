package com.ada.seguranca.aluno;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO de entrada para demonstrar Bean Validation (@Valid) + resposta 400 padronizada
 * sem vazar detalhes internos (ponte para a seção 5 do material do aluno / API de Chamados).
 */
public record NovoAlunoRequest(
        @NotBlank(message = "não pode estar em branco")
        @Size(min = 3, max = 100, message = "deve ter entre 3 e 100 caracteres")
        String nome,

        @NotBlank(message = "não pode estar em branco")
        @Email(message = "deve ser um endereço de e-mail válido")
        String email
) {
}
