package com.example.dz_18.security.entities;

import com.example.dz_18.security.entities.Authority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Set;
import java.util.stream.Collectors;

public enum Role {
    ADMIN(Set.of(Authority.READ, Authority.WRIGHT, Authority.READ_ALL)),
    USER(Set.of(Authority.READ, Authority.READ_ALL));

    private final Set<Authority> authorities;

    Role(Set<Authority> authorities) {
        this.authorities = authorities;
    }

    public  Set<SimpleGrantedAuthority> getAuthorities(){
        return authorities.stream()
                .map(a -> new SimpleGrantedAuthority(a.getAuthoriry()))
                .collect(Collectors.toSet());
    }
}
