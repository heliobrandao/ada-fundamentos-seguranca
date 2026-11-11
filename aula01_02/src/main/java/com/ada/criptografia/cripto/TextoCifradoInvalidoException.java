package com.ada.criptografia.cripto;

public class TextoCifradoInvalidoException extends RuntimeException {

    public TextoCifradoInvalidoException() {
        super("Texto cifrado inválido");
    }
}
