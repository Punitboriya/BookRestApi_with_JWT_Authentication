package com.restapi.book.entities;

import lombok.Builder;
import lombok.Data;
public class JwtResponse {

    private String username;
    private String jwtToken;

    // Private constructor to enforce the use of the builder
    private JwtResponse() {
    }

    public String getUsername() {
        return username;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public static JwtResponseBuilder builder() {
        return new JwtResponseBuilder();
    }

    // Builder class
    public static class JwtResponseBuilder {

        private JwtResponse jwtResponse;

        private JwtResponseBuilder() {
            jwtResponse = new JwtResponse();
        }

        public JwtResponseBuilder username(String username) {
            jwtResponse.username = username;
            return this;
        }

        public JwtResponseBuilder jwtToken(String jwtToken) {
            jwtResponse.jwtToken = jwtToken;
            return this;
        }

        public JwtResponse build() {
            // Validate that all required fields are set
            if (jwtResponse.username == null || jwtResponse.jwtToken == null) {
                throw new IllegalStateException("Username and JWT Token are required fields.");
            }

            // You can perform additional validation if needed

            return jwtResponse;
        }
    }
}

