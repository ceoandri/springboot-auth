package gratis.contoh.auth.service;

public interface AuthorizeValidator {
	
	public Boolean verify(
			String headerValue, String[] roles, String Module, String[] accessType);

}
