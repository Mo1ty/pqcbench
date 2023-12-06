import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.junit.Assert;

import java.security.*;

import static org.junit.Assert.assertTrue;

public class KyberTest {

    public static final String algName = "KYBER";

    public static void initTest() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("!-----------------------------" + algName + "-------------------------------!");
        keyGenSpeedTest();
        encapsDecapsSpeedTest();
        System.out.println("!-------------------------------------------------------------!");
    }

    private static void keyGenSpeedTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastlePQCProvider());
        SecureRandom random = new SecureRandom();
        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber1024));

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

    private static void encapsDecapsSpeedTest() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastlePQCProvider());
        SecureRandom random = new SecureRandom();
        Long encapsTimes = 0L;
        Long decapsTimes = 0L;


        for(int i = 0; i != 1000; ++i) {
            KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
            keyPairGenerator.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber1024));

            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

            Long encapsBefore = System.nanoTime();
            KyberKEMGenerator kemGen = new KyberKEMGenerator(random);
            SecretWithEncapsulation secretEncap = kemGen.generateEncapsulated(keyPair.getPublic());
            Long encapsAfter = System.nanoTime();
            Long encapsTime = encapsAfter - encapsBefore;


            Long decapsBefore = System.nanoTime();
            KyberKEMExtractor kemExtract = new KyberKEMExtractor((KyberPrivateKeyParameters)keyPair.getPrivate());
            byte[] decryptedSharedSecret = kemExtract.extractSecret(secretEncap.getEncapsulation());
            Long decapsAfter = System.nanoTime();
            Long decapsTime = decapsAfter - decapsBefore;

            assertTrue(Arrays.areEqual(secretEncap.getSecret(), decryptedSharedSecret));

            if(i > 900){
                encapsTimes+=encapsTime;
                decapsTimes+=decapsTime;
            }
        }
        System.out.println(algName + " ENCAPS TIME: " + (encapsTimes / 1000));
        System.out.println(algName + " DECAPS TIME: " + (decapsTimes / 1000));
    }
}
