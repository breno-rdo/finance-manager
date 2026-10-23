package com.financemanager.finance_manager.auth;

/** Deliberately vague: it never says whether the email or the password was wrong. */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid email or password.");
    }
}
