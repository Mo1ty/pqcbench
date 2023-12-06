import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sphincsplus.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.junit.Assert;

import java.security.*;

import static org.junit.Assert.assertTrue;

public class SphincsTest {

    public static final String algName = "SPHINCS+";

    public static void initTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("!-----------------------------" + algName + "-------------------------------!");
        keyGenSpeedTest();
        encapsDecapsSpeedTest();
        System.out.println("!-------------------------------------------------------------!");
    }

    private static void keyGenSpeedTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastlePQCProvider());
        SecureRandom random = new SecureRandom();
        SPHINCSPlusKeyPairGenerator keyPairGenerator = new SPHINCSPlusKeyPairGenerator();
        keyPairGenerator.init(new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.shake_256f));

        Long takenTimes = 0L;

        AsymmetricCipherKeyPair prevKeyPair = keyPairGenerator.generateKeyPair();;

        for (int i = 0; i < 200; i++){

            Long timeBefore = System.nanoTime();
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
            Long timeAfter = System.nanoTime();
            Long timeTaken = timeAfter - timeBefore;

            Assert.assertNotEquals(keyPair.getPrivate(), prevKeyPair.getPrivate());
            Assert.assertNotEquals(keyPair.getPublic(), prevKeyPair.getPublic());
            prevKeyPair = keyPair;

            if(i >= 100)
                takenTimes+=timeTaken;
        }

        System.out.println(algName + " KEYGEN TIME: " + (takenTimes / 1000));

    }

    // SHAKE 256_f
    private static void encapsDecapsSpeedTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastlePQCProvider());
        byte[] msg = Strings.toByteArray("Hello World!");
        SecureRandom random = new SecureRandom();
        Long signTimes = 0L;
        Long verifyTimes = 0L;

        SPHINCSPlusKeyPairGenerator kpGen = new SPHINCSPlusKeyPairGenerator();

        for (int i = 0; i < 200; i++){

            kpGen.init(new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.shake_256f));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
            SPHINCSPlusPublicKeyParameters pubParams = (SPHINCSPlusPublicKeyParameters)kp.getPublic();
            SPHINCSPlusPrivateKeyParameters privParams = (SPHINCSPlusPrivateKeyParameters)kp.getPrivate();

            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

            Long signBefore = System.nanoTime();
            signer.init(true, new ParametersWithRandom(privParams, random));
            byte[] sig = signer.generateSignature(msg);
            byte[] attachedSig = Arrays.concatenate(sig, msg);
            Long signAfter = System.nanoTime();
            Long signTime = signAfter - signBefore;

            Long verifyBefore = System.nanoTime();
            signer.init(false, pubParams);
            signer.verifySignature(msg, sig);
            Long verifyAfter = System.nanoTime();
            Long verifyTime = verifyAfter - verifyBefore;

            assertTrue(signer.verifySignature(msg, sig));
            if(i > 100){
                signTimes+=signTime;
                verifyTimes+=verifyTime;
            }
        }

        System.out.println(algName + " SIGN TIME: " + (signTimes / 1000));
        System.out.println(algName + " VERIFY TIME: " + (verifyTimes / 1000));
    }

}
