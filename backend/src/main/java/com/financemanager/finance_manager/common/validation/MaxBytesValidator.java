package com.financemanager.finance_manager.common.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.nio.charset.StandardCharsets;

public class MaxBytesValidator implements ConstraintValidator<MaxBytes, CharSequence> {

    private int max;

    @Override
    public void initialize(MaxBytes constraint) {
        this.max = constraint.value();
    }

    @Override
    public boolean isValid(CharSequence value, ConstraintValidatorContext context) {
        // null is handled by @NotBlank / @NotNull, as is the convention for Bean Validation.
        return value == null || !exceeds(value, max);
    }

    public static boolean exceeds(CharSequence value, int maxBytes) {
        return value != null && value.toString().getBytes(StandardCharsets.UTF_8).length > maxBytes;
    }
}
