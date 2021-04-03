package com.oc.controller;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.json.JSONObject;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken.Access;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.oc.security.KeyCloakUserInfo;

/**
 * @author cksek
 *
 */
@Controller
public class AppController {

	@Value("${trust.store}")
	private Resource trustStore;

	@Value("${trust.store.password}")
	private String trustStorePassword;

	@Value("${keycloak.realm}")
	private String configuredRealm;

	@Value("${keycloak.auth-server-url}")
	private String configuredAuthServer;

	private String configuredIssuer;

	@Autowired
	private HttpServletRequest request;

	/**
	 * 
	 * @return
	 */
	private KeycloakSecurityContext getCurrentSecurityContext() {
		
		if (request.getUserPrincipal() != null) {
			KeycloakAuthenticationToken authenticated = (KeycloakAuthenticationToken) request.getUserPrincipal();
			KeycloakPrincipal<?> usr_principal = (KeycloakPrincipal<?>) authenticated.getPrincipal();
			return usr_principal.getKeycloakSecurityContext();

		} else {
			return null;
		}
	}

	/**
	 * Assign value to the model
	 * 
	 * @return null
	 */
	private KeyCloakUserInfo configModel(Model model) {

		KeyCloakUserInfo usr_info = new KeyCloakUserInfo(getCurrentSecurityContext());
		model.addAttribute("user", usr_info);

		return usr_info;
	}

	/**
	 * Assign value to the model
	 * 
	 * @return null
	 */
	private void configPageModel(Model model, String key, String result) {
		model.addAttribute(key, result);
	}

	@GetMapping("/")
	public String home(Model model) {
		configModel(model);
		return "home";
	}

	@RequestMapping("/sys-support")
	public String displaySysSupport(Model model) {
		
		String METHOD_NM = "displaySysSupport()";
		String targeted_aud = "user-author-sys-support";

		try {

			KeyCloakUserInfo usr_info = configModel(model);
			configPageModel(model, "page", usr_info.getAccessTokenInString());
			
			//Manual verification of ID Token
			verifyIDToken(usr_info.getKeyCloakSecurityContext().getIdToken(), "user-authen-4"); // checking on ID Token if it is valid
			
			/**
			 * Developer may choose 
			 * 1) to verify roles by using resource access from access token 
			 * OR
			 * 2) to verify authorization by using permission ticket from permission token
			 * Both will use different setup in KeyCloak
			 */
			String first_checkpoint = checkAccessToken(usr_info.getKeyCloakSecurityContext(), targeted_aud);
			configPageModel(model, "resource_access", targeted_aud + "=" + first_checkpoint);
			
			String second_checkpoint = checkTicketPermission(usr_info.getKeyCloakSecurityContext(), targeted_aud);
			configPageModel(model, "perm_tic", second_checkpoint.split("\\|")[0]);
			configPageModel(model, "auth_perm", second_checkpoint.split("\\|")[1]);
			configPageModel(model, "perm_res", second_checkpoint.split("\\|")[2]);

		} catch (Exception e) {
			System.err.println(METHOD_NM + " Exception: [" + e.getMessage() + "].");
			configPageModel(model, "error", e.getMessage());
		}

		return "sys-support";
	}
	
	@RequestMapping("/it-sec-admin")
	public String displayITSecAdmin(Model model) {

		String METHOD_NM = "displayITSecAdmin()";
		String targeted_aud = "it-sec-admin";
		
		try {

			KeyCloakUserInfo usr_info = configModel(model);
			configPageModel(model, "page", usr_info.getAccessTokenInString());
			
			//Manual verification of ID Token
			verifyIDToken(usr_info.getKeyCloakSecurityContext().getIdToken(), "user-authen-4"); // checking on ID Token if it is valid
			
			/**
			 * Developer may choose 
			 * 1) to verify roles by using resource access from access token 
			 * OR
			 * 2) to verify authorization by using permission ticket from permission token
			 * Both will use different setup in KeyCloak
			 */
			String first_checkpoint = checkAccessToken(usr_info.getKeyCloakSecurityContext(), targeted_aud);
			configPageModel(model, "resource_access", targeted_aud + "=" + first_checkpoint);
			
			String second_checkpoint = checkTicketPermission(usr_info.getKeyCloakSecurityContext(), targeted_aud);
			configPageModel(model, "perm_tic", second_checkpoint.split("\\|")[0]);
			configPageModel(model, "auth_perm", second_checkpoint.split("\\|")[1]);
			configPageModel(model, "perm_res", second_checkpoint.split("\\|")[2]);

		} catch (Exception e) {
			System.err.println(METHOD_NM + " Exception: [" + e.getMessage() + "].");
			configPageModel(model, "error", e.getMessage());
		}

		return "it-sec-admin";
	}

	private String checkAccessToken(KeycloakSecurityContext sc, String targeted_aud) {
		
		String METHOD_NM = "checkAccessToken()";
		
		StringBuffer supported_roles = new StringBuffer();
		
		Access rs_access = sc.getToken().getResourceAccess().get(targeted_aud);
		
		if (!(rs_access == null)) {
			Iterator<String> iter = rs_access.getRoles().iterator();
			
			while (iter.hasNext()) {
				supported_roles.append(iter.next()).append(", ");
			}
		}
		
		System.out.println(METHOD_NM + "result [" + supported_roles.toString() + "].");
		
		return supported_roles.length() == 0 ? "":supported_roles.toString().substring(0, supported_roles.length() - 2);
	}
	
	private String checkTicketPermission(KeycloakSecurityContext sc, String targeted_aud) throws Exception {

		String METHOD_NM = "checkTicketPermission()";
		configuredIssuer = configuredAuthServer + "/realms/" + configuredRealm;

		RestTemplate restful = restTemplate();
		HttpHeaders headers = new HttpHeaders();
		HttpEntity<MultiValueMap<String, String>> entity;
		ResponseEntity<String> resp;
		JSONObject obj;
		
		//Requesting Permission Ticket from KeyCloak
		headers.add("Authorization", "Bearer " + sc.getTokenString());
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
		map.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
		map.add("audience", targeted_aud);

		entity = new HttpEntity<MultiValueMap<String, String>>(map, headers);
		resp = restful.exchange(configuredIssuer + "/protocol/openid-connect/token", HttpMethod.POST, entity, String.class);

		System.out.println(METHOD_NM + "Response from Key Cloak: [" + resp.getBody() + "].");
		
		// Forming JSON Object with response from key cloak
		obj = new JSONObject(resp.getBody());

		// Form JsonWebToken based on permission ticket (access token)
		JsonWebToken jwt = TokenVerifier.create(obj.get("access_token").toString(), JsonWebToken.class).getToken();
		
		/**
		 * Developer may verify permission ticket by using following options
		 * 1) Manual check for permission granted to users (based on resources)
		 * OR
		 * 2) Manual check for resources & roles granted to users
		 * This POC having 2 method of checking for developer references.
		 */
		// Method 1:
		Map<?,?> auth = (LinkedHashMap<?,?>)jwt.getOtherClaims().get("authorization");
		List<?> auth_permission = (List<?>) auth.get("permissions");

		for (int i = 0 ; i < auth_permission.size() ; i++) {
			System.out.println(METHOD_NM + "Count [" + (i+1) + "]-"+ auth_permission.get(i));
			//TODO teams can cross check with the resource value and its scopes to determine the access
		}

		// Method 2:
		Map<?,?> auth_resource = (LinkedHashMap<?,?>)jwt.getOtherClaims().get("resource_access");
		System.out.println(METHOD_NM + "Resource Access Class [" + auth_resource.keySet()+ "].");
		
		for (int i = 0 ; i < auth_resource.size() ; i++) {
			System.out.println(METHOD_NM + "Count [" + (i+1) + "]-"+ auth_resource.get(targeted_aud)); //TODO to be define based on the user configuration
			//TODO teams can cross check with the roles assigned to users to determine if it is accessible.
		}
		
		return obj.get("access_token").toString() + "|" + auth_permission.toString() + "|" + auth_resource.get(targeted_aud);
	}

	private RestTemplate restTemplate() throws Exception {

		SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(trustStore.getURL(), trustStorePassword.toCharArray()).build();
		SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
		HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build();
		HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

		return new RestTemplate(factory);
	}
	
	public void verifyIDToken(IDToken token, String targeted_aud) {
		
		try {
			
			TokenVerifier<IDToken> verifier = TokenVerifier.createWithoutSignature(token);
			verifier.issuedFor("user-authen-4"); //check for authorized parties
			verifier.audience(targeted_aud); //check for audience
			verifier.verify();
		} catch (JWTVerificationException e){
		    e.printStackTrace();
		} catch (VerificationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
