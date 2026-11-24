import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * Reproduction aid, not part of SandMark: a JCA provider whose Blowfish
 * KeyGenerator returns the key recorded by a retained SandMark GTW embedding
 * instead of drawing fresh OS entropy. The retained key file is
 * {replay}/{case-id}/embed/gtw.key, where {replay} is the system property
 * toolchainmark.gtw.key.replay and {case-id} is the parent of the working
 * directory (the adapter runs each embed in {case}/embed). A missing key fails.
 */
public final class GtwKeyReplay extends Provider {
    public GtwKeyReplay() {
        super("ToolchainMarkGtwKeyReplay", "1.0", "Replays retained SandMark GTW Blowfish keys");
        put("KeyGenerator.Blowfish", Spi.class.getName());
    }

    public static final class Spi extends KeyGeneratorSpi {
        protected void engineInit(SecureRandom random) { }
        protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) { }
        protected void engineInit(int keysize, SecureRandom random) { }
        protected SecretKey engineGenerateKey() {
            String replay = System.getProperty("toolchainmark.gtw.key.replay");
            if (replay == null) throw new IllegalStateException("toolchainmark.gtw.key.replay is not set");
            File work = new File(System.getProperty("user.dir")).getAbsoluteFile();
            File key = new File(new File(new File(replay, work.getParentFile().getName()), "embed"), "gtw.key");
            try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(key))) {
                return (SecretKey) in.readObject();
            } catch (Exception problem) {
                throw new IllegalStateException("cannot replay retained GTW key " + key, problem);
            }
        }
    }
}
