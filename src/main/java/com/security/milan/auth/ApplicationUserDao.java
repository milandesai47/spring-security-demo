package com.security.milan.auth;

import java.util.Optional;

public interface ApplicationUserDao {

    public Optional<ApplicationUser> selectionApplicationUserByUsername(String username);
}
