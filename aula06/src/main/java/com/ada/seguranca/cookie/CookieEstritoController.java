package com.ada.seguranca.cookie;

import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint trazido da aula 02 para demonstrar a armadilha do @ExceptionHandler(Exception.class):
 * Sem o cookie "user-id", o Spring MVC lança MissingRequestCookieException (status 400).
 * Se o GlobalExceptionHandler NÃO estender ResponseEntityExceptionHandler, o handler genérico
 * de Exception engole esse erro e devolve 500 Internal Server Error por engano!
 */
@RestController
public class CookieEstritoController {

    @GetMapping("/boas-vindas")
    public String boasVindas(
            @CookieValue(name = "user-id", defaultValue = "default-user-id") String userId) {
        return "Olá, usuário " + userId;
    }

    @GetMapping("/boas-vindas/estrito")
    public String boasVindasEstrito(@CookieValue(name = "user-id") String userId) {
        return "Olá, usuário " + userId;
    }
}
