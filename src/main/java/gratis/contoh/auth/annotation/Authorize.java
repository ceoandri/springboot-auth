package gratis.contoh.auth.annotation;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import gratis.contoh.auth.constant.AuthTypes;
import gratis.contoh.auth.constant.HeaderTypes;

@Retention(RUNTIME)
@Target({ METHOD })
public @interface Authorize {

	String header() default HeaderTypes.AUTHORIZATION;
	
	String authType() default AuthTypes.BEARER;

	String[] roles() default {};
	
	String module() default "";
	
	String[] accessTypes() default {};
	
}
