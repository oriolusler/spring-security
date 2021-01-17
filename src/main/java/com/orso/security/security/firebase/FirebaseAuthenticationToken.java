package com.orso.security.security.firebase;

import com.orso.security.models.FirebaseCredentials;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Objects;

@Transient
public class FirebaseAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -1869548136546750302L;

    private final UserDetails token;
    private FirebaseCredentials credentials;


    public FirebaseAuthenticationToken(UserDetails principal, Object credentials,
                                       Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = principal;
        this.credentials = (FirebaseCredentials) credentials;
        super.setAuthenticated(true); // must use super, as we override
    }
    // ~ Methods
    // ========================================================================================================

    public Object getCredentials() {
        return this.credentials;
    }

    public Object getPrincipal() {
        return token;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        FirebaseAuthenticationToken that = (FirebaseAuthenticationToken) o;
        return Objects.equals(token, that.token) && Objects.equals(credentials, that.credentials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), token, credentials);
    }

    @Override
    public String toString() {
        return "FirebaseAuthenticationToken{" +
                "principal=" + token +
                ", credentials=" + credentials +
                '}';
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }
}