package com.sample.exception;

public class ClientAppException extends Exception {

    public ClientAppException(String message) {

        super(message);
    }

    public ClientAppException(String message, Throwable cause) {

        super(message, cause);
    }
}
