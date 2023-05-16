package gratis.contoh.auth.exception;

public class UnauthenticateException extends RuntimeException {
	
	private static final long serialVersionUID = 2812613517227857948L;

	public UnauthenticateException(String error) {
        super(error);
    }

}
