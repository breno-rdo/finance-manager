package com.financemanager.finance_manager.auth.dto;

import com.financemanager.finance_manager.user.Role;
import com.financemanager.finance_manager.user.User;

public record UserResponse(Long id, String email, Role role) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getRole());
    }
}
