package com.etiennek.auth.core.model.func;

import java.time.LocalDateTime;

@FunctionalInterface
public interface GetNow {
  LocalDateTime getNow();
}
