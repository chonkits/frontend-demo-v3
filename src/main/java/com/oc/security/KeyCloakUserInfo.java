package com.oc.security;

import java.util.List;

import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;

/**
 * @author cksek
 *
 */
public class KeyCloakUserInfo {

	private final KeycloakSecurityContext securityContext;
	
	public KeyCloakUserInfo(KeycloakSecurityContext securityContext) {
		this.securityContext = securityContext;
	}
	
	/**
	 * Return name for current logged user
	 * @return
	 */
	public String getName() {
		
		String name = "";
		
		if (securityContext != null) {
			name = securityContext.getIdToken().getPreferredUsername();
		}
		
		return name;
	}
	
	public KeycloakSecurityContext getKeyCloakSecurityContext() {
		return securityContext;
	}
	/**
	 * Return name for current logged user
	 * @return
	 */
	public String getAccessTokenInString() {
		
		String access_token_str = null;
		
		if (securityContext != null) {
			access_token_str = securityContext.getTokenString();
		}
		
		return access_token_str;
	}
	
	/**
	 * Return name for current logged user
	 * @return
	 */
	public AccessToken getAccessToken() {
		
		AccessToken access_token = null;
		
		if (securityContext != null) {
			access_token = securityContext.getToken();
		}
		
		return access_token;
	}
	
	/**
	 * Return assigned permission for current user
	 * @return
	 */
	public List<Permission> getUserPermission() {
		return securityContext.getAuthorizationContext().getPermissions();
	}
	
	/**
	 * Return authorization context for current user
	 * @return
	 */
	public AuthorizationContext getUserAuthorizationContext() {
		return securityContext.getAuthorizationContext();
	}
	
}
