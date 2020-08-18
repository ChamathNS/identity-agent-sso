package com.sample.exception;

public class SampleAppServerException extends Exception {

    public SampleAppServerException(final String message) {

        super(message);
    }

    public SampleAppServerException(final String message, final Throwable ex) {

        super(message, ex);
    }

}
