import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.*;
import org.bouncycastle.pqc.crypto.sphincsplus.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.junit.Assert;

import java.security.*;

import static org.junit.Assert.assertTrue;

public class FalconTest {

    public static final String algName = "FALCON";

    public static void initTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("!-----------------------------" + algName + "-------------------------------!");
        keyGenSpeedTest();
        encapsDecapsSpeedTest();
        System.out.println("!-------------------------------------------------------------!");
    }

    private static void keyGenSpeedTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastlePQCProvider());
        SecureRandom random = new SecureRandom();
        FalconKeyPairGenerator keyPairGenerator = new FalconKeyPairGenerator();
        keyPairGenerator.init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_512));

        Long takenTimes = 0L;

        AsymmetricCipherKeyPair prevKeyPair = keyPairGenerator.generateKeyPair();;

        for (int i = 0; i < 1000; i++){

            Long timeBefore = System.nanoTime();
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
            Long timeAfter = System.nanoTime();
            Long timeTaken = timeAfter - timeBefore;

            Assert.assertNotEquals(keyPair.getPrivate(), prevKeyPair.getPrivate());
            Assert.assertNotEquals(keyPair.getPublic(), prevKeyPair.getPublic());
            prevKeyPair = keyPair;

            if(i >= 900)
                takenTimes+=timeTaken;
        }

        System.out.println(algName + " KEYGEN TIME: " + (takenTimes / 1000));

    }

    // SHAKE 256_f
    private static void encapsDecapsSpeedTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastlePQCProvider());
        byte[] msg = Strings.toByteArray("Hello World!");

        FalconKeyPairGenerator keyGen = new FalconKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        keyGen.init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_512));

        Long signTimes = 0L;
        Long verifyTimes = 0L;

        for (int i = 0; i < 1000; i++){

            AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
            FalconSigner signer = new FalconSigner();
            FalconPrivateKeyParameters skparam = (FalconPrivateKeyParameters)keyPair.getPrivate();
            ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);

            Long signBefore = System.nanoTime();
            signer.init(true, skwrand);
            byte[] sigGenerated = signer.generateSignature(msg);
            Long signAfter = System.nanoTime();
            Long signTime = signAfter - signBefore;

            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)keyPair.getPublic();

            Long verifyBefore = System.nanoTime();
            verifier.init(false, pkparam);
            verifier.verifySignature(msg, sigGenerated);
            Long verifyAfter = System.nanoTime();
            Long verifyTime = verifyAfter - verifyBefore;

            assertTrue("count = " + i, verifier.verifySignature(msg, sigGenerated));

            if(i > 900){
                signTimes+=signTime;
                verifyTimes+=verifyTime;
            }
        }

        System.out.println(algName + " SIGN TIME: " + (signTimes / 1000));
        System.out.println(algName + " VERIFY TIME: " + (verifyTimes / 1000));
    }

}
