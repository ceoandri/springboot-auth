package gratis.contoh.auth.service;

public interface AuthorizeValidator {
	
	public Boolean isAuthenticate(String headerValue);
	
	public Boolean isAuthorize(
			String headerValue, String[] roles, String module, String[] accessType);

}
