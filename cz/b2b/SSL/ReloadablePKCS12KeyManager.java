package cz.b2b.SSL;

import java.security.cert.CertificateException;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.security.cert.Certificate;
import java.util.concurrent.atomic.*;
import java.io.*;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Automatically renewable KeyManager.
 *
 * The key/certificate is in PKCS12 format. The KeyManager automatically renews
 * before the certificate stored here expires.
 *
 * @author Richard Kotal
 */
public class ReloadablePKCS12KeyManager implements X509KeyManager {

    private static final Logger logger = LoggerFactory.getLogger(ReloadablePKCS12KeyManager.class);

    private String ssl_key_file = null;
    private String ssl_key_password = null;
    private final AtomicReference<X509KeyManager> keyManager = new AtomicReference<>(null);
    private final AtomicReference<KeyStore> ks = new AtomicReference<>(null);
    private char[] ssl_password = null;
    private final String keystore_type = "PKCS12";
    private final AtomicLong not_after = new AtomicLong(-1L);
    private long ssl_key_store_reload_ms = -1L;

    /**
     * Automatically renewable KeyManager.
     *
     * The key/certificate is in PKCS12 format. The KeyManager automatically
     * renews before the certificate stored here expires.
     *
     * @param ssl_key_file Path to the key/certificate file in PKCS12 format.
     * @param ssl_key_password Password for this certificate file.
     * @param ssl_key_store_reload_ms Time period indicating when the
     * certificate should be automatically renewed before expiration (it is
     * assumed that the corresponding certificate file is already up-to-date).
     * Given in ms. For example, 86400000 means 24 hours before the certificate
     * expires.
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    public ReloadablePKCS12KeyManager(
            String ssl_key_file,
            String ssl_key_password,
            long ssl_key_store_reload_ms
    ) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {
        this.ssl_key_file = ssl_key_file;
        this.ssl_key_password = ssl_key_password;
        this.ssl_key_store_reload_ms = ssl_key_store_reload_ms;
        if (Utils.empty(this.ssl_key_password) == false) {
            ssl_password = this.ssl_key_password.toCharArray();
        }
        reload();
    }

    /**
     * Reload the given certificate from the PKCS12 file.
     *
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    public final void reload() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException {

        _set_key_store();
        _set_keyManager();
        _set_not_after();
        logger.info("Reloaded certificates: " + namesOfCertificates() + ", notAfter: " + new Date(not_after.get()));

    }

    /**
     * List of certificate names stored in KeyManager.
     *
     * @return
     * @throws KeyStoreException
     */
    public List<String> namesOfCertificates() throws KeyStoreException {
        List<String> names = new ArrayList<>();
        Enumeration<String> aliases = null;
        if (ks.get() == null) {
            return names;
        }
        aliases = ks.get().aliases();
        if (aliases == null) {
            return names;
        }
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.get().getCertificate(alias);
            if (cert == null) {
                continue;
            }
            names.add(Utils.X509CertificateSubjectName(cert));
        }
        return names;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        _reload_keys();
        if (_key_manager() != null) {
            return _key_manager().getClientAliases(keyType, issuers);
        }
        return null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        _reload_keys();

        if (_key_manager() != null) {
            return _key_manager().chooseClientAlias(keyType, issuers, socket);
        }
        return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        _reload_keys();

        if (_key_manager() != null) {
            return _key_manager().getServerAliases(keyType, issuers);
        }
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        _reload_keys();

        if (_key_manager() != null) {
            return _key_manager().chooseServerAlias(keyType, issuers, socket);
        }
        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        _reload_keys();

        if (_key_manager() != null) {
            return _key_manager().getCertificateChain(alias);
        }
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        _reload_keys();

        if (_key_manager() != null) {
            return _key_manager().getPrivateKey(alias);
        }
        return null;
    }

    ///////////////// PRIVATE

    private X509KeyManager _key_manager() {
        return keyManager.get();
    }

    private void _set_keyManager() throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        if (ks.get() == null) {
            return;
        }
        // initialize a new TMF with the ts we just loaded
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks.get(), ssl_password);

        // acquire X509 trust manager from factory
        KeyManager[] kms = kmf.getKeyManagers();
        for (KeyManager tm : kms) {
            if (tm instanceof X509KeyManager x509KeyManager) {
                keyManager.set(x509KeyManager);
                return;
            }
        }

        throw new NoSuchAlgorithmException("No X509KeyManager in KeyManagerFactory");

    }

    private FileInputStream _ssl_key_file_inputstream() throws KeyStoreException, FileNotFoundException {
        FileInputStream is = null;
        File f = new File(ssl_key_file);
        if (!f.exists()) {
            throw new KeyStoreException("The file = " + ssl_key_file + "does not exist.");
        }
        is = new FileInputStream(f);

        return is;
    }

    private void _set_key_store() {
        FileInputStream is = null;
        try {

            is = _ssl_key_file_inputstream();
            if (is == null) {
                return;
            }
            ks.set(KeyStore.getInstance(keystore_type));
            ks.get().load(is, ssl_password);

        } catch (Exception e) {
            logger.error("Keystore initialization ended by exception", e);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Exception e) {
                logger.error("InputStream closing ended by exception", e);
            }
        }

    }

    private void _reload_keys() {
        if (ssl_key_store_reload_ms < 0L) {
            return;
        }
        long now = System.currentTimeMillis();
        if (not_after.get() == -1L) {
            return;
        }
        if (now >= (not_after.get() - ssl_key_store_reload_ms)) {
            try {
                reload();
            } catch (Exception e) {
                logger.error("Keystore reloading ended by exception", e);
            }
        }
    }

    private void _set_not_after() throws KeyStoreException {
        Enumeration<String> aliases = null;
        if (ks.get() == null) {
            return;
        }
        aliases = ks.get().aliases();
        if (aliases == null) {
            return;
        }
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.get().getCertificate(alias);
            if (cert == null) {
                continue;
            }
            long notafter = Utils.X509CertificateNotAfter(cert);
            if (notafter == -1L) {
                continue;
            }
            if (not_after.get() == -1L) {
                not_after.set(notafter);
                continue;
            }
            if (notafter < not_after.get()) {
                not_after.set(notafter);
            }
        }

    }

}
