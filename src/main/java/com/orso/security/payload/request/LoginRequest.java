package com.orso.security.payload.request;

import com.orso.security.models.EAuthType;

import javax.validation.constraints.NotBlank;

public class LoginRequest {
	//@NotBlank
	private String username;

	//@NotBlank
	private String password;

	private EAuthType authType;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public EAuthType getAuthType() {
		return authType;
	}

	public void setAuthType(EAuthType authType) {
		this.authType = authType;
	}
}
