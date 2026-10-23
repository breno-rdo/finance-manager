package com.financemanager.finance_manager.auth;

public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("Refresh token is invalid or expired.");
    }
}
