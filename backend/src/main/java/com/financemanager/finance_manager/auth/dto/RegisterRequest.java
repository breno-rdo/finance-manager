package com.financemanager.finance_manager.auth.dto;

import com.financemanager.finance_manager.common.validation.MaxBytes;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank @Email @Size(max = 255) String email,
        // 72 is BCrypt's limit, measured in bytes (see AuthService.MAX_PASSWORD_BYTES).
        @NotBlank @Size(min = 8) @MaxBytes(72) String password) {
}
