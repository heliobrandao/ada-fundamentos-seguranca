package com.ada.seguranca.exception;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Simula uma falha interna inesperada que contém detalhes sensíveis da infraestrutura
 * (URL do banco H2, usuário do banco, nome de tabela).
 *
 * Serve para demonstrar a "rede de segurança" do GlobalExceptionHandler:
 * - No log do servidor: aparece a stack trace completa com "jdbc:h2:mem:testdb".
 * - Na resposta HTTP (500): o cliente recebe apenas "Erro interno. Tente novamente mais tarde."
 */
@RestController
public class ErroTesteController {

    @GetMapping("/erro-teste")
    public String erroTeste() {
        throw new IllegalStateException(
                "Falha ao executar SELECT na conexão jdbc:h2:mem:testdb (usuário=sa, tabela=alunos)"
        );
    }
}
