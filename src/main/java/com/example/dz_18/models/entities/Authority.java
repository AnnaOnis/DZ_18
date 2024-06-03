package com.example.dz_18.security.entities;

import lombok.ToString;

public enum Authority {
    READ_ALL,
    READ,
    WRIGHT;

    public String getAuthoriry(){
        return toString();
    }
}
