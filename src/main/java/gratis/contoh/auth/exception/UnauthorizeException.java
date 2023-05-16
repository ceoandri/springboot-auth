package gratis.contoh.auth.exception;

public class UnauthorizeException extends RuntimeException {
	
	private static final long serialVersionUID = 2812613517227857948L;

	public UnauthorizeException(String error) {
        super(error);
    }

}
