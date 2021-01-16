package com.orso.security.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "auth_type")
public class AuthType {
  @Id
  private String id;

  private EAuthType name;

  public AuthType() {

  }

  public AuthType(EAuthType name) {
    this.name = name;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public EAuthType getName() {
    return name;
  }

  public void setName(EAuthType name) {
    this.name = name;
  }
}
