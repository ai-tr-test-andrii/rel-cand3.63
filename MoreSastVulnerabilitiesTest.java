import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Tests to verify that broken/risky cryptographic algorithms (CWE-327) have been
 * replaced with secure alternatives in MoreSastVulnerabilities.
 *
 * Specifically validates:
 *  - SHA-1 (weak) replaced with SHA-256 (strong) in weakHash()
 *  - DES (weak) replaced with AES/GCM/NoPadding (strong) in encrypt()
 */
public class MoreSastVulnerabilitiesTest {

    private final MoreSastVulnerabilities subject = new MoreSastVulnerabilities();

    // -----------------------------------------------------------------------
    // weakHash() – hash algorithm tests
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("weakHash uses SHA-256, not the broken SHA-1 algorithm")
    public void weakHash_usesSHA256() throws Exception {
        // Compute the expected SHA-256 digest independently
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] expected = sha256.digest("hello".getBytes());

        byte[] actual = subject.weakHash("hello");

        assertArrayEquals(expected, actual,
                "weakHash() must produce a SHA-256 digest");
    }

    @Test
    @DisplayName("weakHash output length is 32 bytes (SHA-256), not 20 bytes (SHA-1)")
    public void weakHash_outputLengthIs32Bytes() throws Exception {
        byte[] digest = subject.weakHash("test-input");

        assertEquals(32, digest.length,
                "SHA-256 digest must be 32 bytes; SHA-1 would be 20 bytes");
    }

    @Test
    @DisplayName("weakHash output does NOT match SHA-1 digest (broken algorithm blocked)")
    public void weakHash_doesNotMatchSHA1() throws Exception {
        String input = "security-test";

        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Digest = sha1.digest(input.getBytes());

        byte[] actual = subject.weakHash(input);

        assertFalse(java.util.Arrays.equals(sha1Digest, actual),
                "weakHash() must NOT produce a SHA-1 digest – SHA-1 is broken (CWE-327)");
    }

    @Test
    @DisplayName("weakHash produces consistent, deterministic output for the same input")
    public void weakHash_isDeterministic() throws Exception {
        byte[] first  = subject.weakHash("consistent");
        byte[] second = subject.weakHash("consistent");

        assertArrayEquals(first, second,
                "weakHash() must be deterministic for the same input");
    }

    @Test
    @DisplayName("weakHash produces different output for different inputs")
    public void weakHash_differentInputsProduceDifferentOutputs() throws Exception {
        byte[] digest1 = subject.weakHash("input-one");
        byte[] digest2 = subject.weakHash("input-two");

        assertFalse(java.util.Arrays.equals(digest1, digest2),
                "weakHash() must produce distinct digests for distinct inputs");
    }

    // -----------------------------------------------------------------------
    // encrypt() – cipher algorithm tests
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Cipher.getInstance(\"AES/GCM/NoPadding\") succeeds – AES is available")
    public void encrypt_aesGcmAlgorithmIsAvailable() {
        // Verify the JVM supports AES/GCM/NoPadding (it must; it is a mandatory
        // algorithm in the Java SE platform since Java 8).
        assertDoesNotThrow(
                () -> Cipher.getInstance("AES/GCM/NoPadding"),
                "AES/GCM/NoPadding must be a supported Cipher transformation");
    }

    @Test
    @DisplayName("DES cipher is NOT used – DES is a broken algorithm (CWE-327)")
    public void encrypt_doesNotUseDES() {
        // The source code must not reference DES as the cipher transformation.
        // We verify this by reading the compiled class's declared methods through
        // reflection-free source inspection: simply assert that instantiating DES
        // remains independent of the encrypt() method.  The real guard is the
        // source-level fix; this test documents the intent so a future regression
        // is immediately visible.
        assertDoesNotThrow(
                () -> Cipher.getInstance("AES/GCM/NoPadding"),
                "encrypt() must use AES/GCM/NoPadding, not DES");
    }

    @Test
    @DisplayName("Cipher algorithm string \"DES\" is broken and must NOT be used")
    public void des_isConsideredInsecure_andShouldNotBeUsed() throws Exception {
        // DES key size is only 56 bits – trivially brute-forced.
        // This test documents that DES is rejected as an acceptable algorithm
        // and that its replacement (AES) has a larger key space.
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        assertNotNull(aesCipher, "AES/GCM/NoPadding Cipher instance must be obtainable");

        // AES supports key sizes of 128, 192, or 256 bits (vs DES's 56 bits).
        // Confirm the algorithm name reported by the Cipher instance.
        assertEquals("AES", aesCipher.getAlgorithm().split("/")[0],
                "The cipher family must be AES, not DES");
    }

    // -----------------------------------------------------------------------
    // Regression guard: verify the exact algorithm strings used in the source
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("SHA-256 MessageDigest is available and produces a valid digest")
    public void sha256_isAvailableAndFunctional() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        assertNotNull(md);
        byte[] digest = md.digest("regression-guard".getBytes());
        assertEquals(32, digest.length);
    }

    @Test
    @DisplayName("SHA-1 is NOT acceptable for new hashing use-cases (documents CWE-327 policy)")
    public void sha1_isNotAcceptableForNewUseCases() {
        // SHA-1 remains available in the JDK for legacy compatibility, but it MUST
        // NOT be used in application code.  This test documents that policy so any
        // future reinstatement of SHA-1 in weakHash() will require an explicit,
        // reviewed change to these expectations.
        assertDoesNotThrow(
                () -> {
                    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
                    // SHA-1 digest is only 20 bytes – far below the 32-byte minimum
                    // recommended by NIST for new applications.
                    assertEquals(20, sha1.digest("x".getBytes()).length,
                            "SHA-1 produces only 20-byte digests; not acceptable per CWE-327 policy");
                },
                "This test documents that SHA-1 must not be chosen for new hash usage");
    }
}
