package gratis.contoh.auth.catcher;

import jakarta.servlet.http.HttpServletRequest;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import gratis.contoh.auth.annotation.Authorize;
import gratis.contoh.auth.constant.AuthTypes;
import gratis.contoh.auth.exception.UnauthenticateException;
import gratis.contoh.auth.exception.UnauthorizeException;
import gratis.contoh.auth.service.AuthorizeValidator;

@Aspect
@Component
public class AuthorizeCatcher {
	
	@Pointcut("@annotation(authorize)")
	private void authorizeData(Authorize authorize) {}
	
	@Autowired
	private AuthorizeValidator validator;
	
	@Before("authorizeData(authorize)")
    public void before(Authorize authorize) throws UnauthenticateException, UnauthorizeException  {
        HttpServletRequest request = 
        		((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();

        String headerName = authorize.header();
		String authType = authorize.authType();
		String[] roles = authorize.roles();
		String module = authorize.module();
		String[] accessTypes = authorize.accessTypes();
		
		String headerValue = request.getHeader(headerName);
		
		if (headerValue != null) {
			if (!this.validator.isAuthenticate(headerValue)) {
				throw new UnauthenticateException("please login to access this resource");
			}
			
			boolean res = authorizeHeader(authType, headerValue, roles, module, accessTypes);
			
			if (!res) {
				throw new UnauthorizeException("you don't have permission to access this resource");
			}
		} else {
			throw new UnauthenticateException("please login to access this resource");
		}
    }
	
	private Boolean authorizeHeader(
			String authType, 
			String token, 
			String[] roles, 
			String module, 
			String[] accessTypes) {
		switch (authType) {
			case AuthTypes.BEARER: {
				if (token.startsWith("Bearer ")) {
					return this.validator.isAuthorize(token.split(" ")[1], roles, module, accessTypes);				
				} else {
					return false;
				}
			}
			case AuthTypes.BASIC: {
				if (token.startsWith("Basic ")) {
					return this.validator.isAuthorize(token.split(" ")[1], roles, module, accessTypes);
				} else {
					return false;
				}
			}
			default: {
				return this.validator.isAuthorize(token.split(" ")[1], roles, module, accessTypes);
			}
		}
	}

}
