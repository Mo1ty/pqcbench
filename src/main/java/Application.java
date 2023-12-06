import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Application {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KyberTest.initTest();
        DilithiumTest.initTest();
        FalconTest.initTest();
        SphincsTest.initTest();
    }

}
