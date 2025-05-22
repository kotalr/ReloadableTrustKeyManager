package cz.b2b.SSL;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.security.cert.Certificate;
import java.util.concurrent.atomic.AtomicReference;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Automatically renewable TrustManager.
 *
 * Certificates are renewed either from permanent storage (disk) or from memory
 * where they were temporarily stored when newly received by the system.
 * Certificates are in PEM format. Certificates are renewed whenever the system
 * detects that it has received a certificate that it does not know.
 *
 *
 * @author Richard Kotal
 */
public abstract class ReloadableX509TrustManager implements X509TrustManager {

    private static final Logger logger = LoggerFactory.getLogger(ReloadableX509TrustManager.class);

    private String ssl_certificates_directory = null;
    private String ssl_certificates_suffix = null;
    private String ssl_certificates_store = null;
    private String ssl_certificates_type = null;
    private String ssl_trust_store = null;
    private final List<Certificate> CERTS_CACHE = new CopyOnWriteArrayList<>();
    private final AtomicReference<X509TrustManager> trustManager = new AtomicReference<>(null);
    private final AtomicReference<KeyStore> ks = new AtomicReference<>(null);

    /**
     * Automatically renewable TrustManager.
     *
     * Certificates are renewed either from permanent storage (disk) or from
     * memory where they were temporarily stored when newly received by the
     * system. Certificates are in PEM format. Certificates are renewed whenever
     * the system detects that it has received a certificate that it does not
     * know.
     *
     * @param ssl_certificates_directory A comma-separated list of directories
     * where certificates to be uploaded to TrustManager are permanently stored.
     * The directories are traversed recursively.
     * @param ssl_certificates_suffix The extension of the certificate file
     * names. Only files with the specified extension are loaded. For example:
     * .pem.
     * @param ssl_certificates_store Specifies what to do with a newly obtained
     * unknown certificate. Possible values ​​off=renew disabled; manually=only
     * a log entry and notification that an unknown certificate was received;
     * temporarily=the certificate is temporarily stored in RAM and loaded into
     * TrustManager, information about this is written to the log and
     * notifications are sent; permanently=the certificate is permanently stored
     * in the ssl_trust_store directory with the ssl_certificates_suffix
     * extension and loaded into TrustManager, information about this is written
     * to the log and notifications are sent.
     * @param ssl_certificates_type Type of certificates permanently stored.
     * Typical value: X.509
     * @param ssl_trust_store Directory where newly obtained certificates will
     * be automatically stored if ssl_certificates_store=permanently.
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     */
    public ReloadableX509TrustManager(
            String ssl_certificates_directory,
            String ssl_certificates_suffix,
            String ssl_certificates_store,
            String ssl_certificates_type,
            String ssl_trust_store
    ) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        this.ssl_certificates_directory = ssl_certificates_directory;
        this.ssl_certificates_suffix = ssl_certificates_suffix;
        if (ssl_certificates_store == null) {
            ssl_certificates_store = Utils.off;
        }
        this.ssl_certificates_store = ssl_certificates_store;
        this.ssl_certificates_type = ssl_certificates_type;
        this.ssl_trust_store = ssl_trust_store;

        reload();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        if (_trust_manager() != null) {
            try {
                _trust_manager().checkClientTrusted(chain, authType);
            } catch (CertificateException cx) {
                try {
                    _add_reload_server_cert(chain);
                } catch (Exception e) {
                    logger.error("Truststore reloading ended by exception", e);
                }
                _trust_manager().checkClientTrusted(chain, authType);
            }
        } else {
            throw new CertificateException("No X509TrustManager in TrustManagerFactory");
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        if (_trust_manager() != null) {
            try {
                _trust_manager().checkServerTrusted(chain, authType);
            } catch (CertificateException cx) {
                try {
                    _add_reload_server_cert(chain);
                } catch (Exception e) {
                    logger.error("Truststore reloading ended by exception", e);
                }
                _trust_manager().checkServerTrusted(chain, authType);
            }
        } else {
            throw new CertificateException("No X509TrustManager in TrustManagerFactory");
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] issuers = null;

        if (_trust_manager() != null) {
            issuers = _trust_manager().getAcceptedIssuers();
        }
        return issuers;
    }

    /**
     * Reloads certificates from both permanent (disk) and temporary (RAM)
     * storage into TrustManager.
     *
     *
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     */
    public final void reload() throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {

        _set_key_store();
        _reload_server_cert_temporarily();
        _reload_server_cert_permanently();
        _set_trustManager();

    }

    /**
     * List of certificate issuer names stored in TrustManager.
     *
     * @return
     */
    public List<String> namesOfAcceptedIssuers() {
        X509Certificate[] issuers = getAcceptedIssuers();
        List<String> names = new ArrayList<>();
        if (issuers == null) {
            return names;
        }
        for (X509Certificate cert : issuers) {
            if (cert == null) {
                continue;
            }
            names.add(Utils.X509CertificateSubjectName(cert));
        }
        return names;
    }

    /**
     * List of certificate names stored in TrustManager.
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

    /**
     * Method for notification of obtaining and storing a new certificate (for
     * example email).
     *
     * @param subject Subject, what should be notified.
     * @param msg Message that needs to be notified.
     * @param hostname Hostname where the event originated.
     */
    public abstract void notify(String subject, String msg, String hostname);

    ///////////////// PRIVATE
    private X509TrustManager _trust_manager() {
        return trustManager.get();
    }

    private void _set_trustManager() throws NoSuchAlgorithmException, KeyStoreException {
        if (ks.get() == null) {
            return;
        }
        // initialize a new TMF with the ts we just loaded
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks.get());

        // acquire X509 trust manager from factory
        TrustManager tms[] = tmf.getTrustManagers();
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager x509TrustManager) {
                trustManager.set(x509TrustManager);
                return;
            }
        }

        throw new NoSuchAlgorithmException("No X509TrustManager in TrustManagerFactory");

    }

    private void _set_key_store() {
        try {
            ks.set(KeyStore.getInstance(KeyStore.getDefaultType()));
            ks.get().load(null);

        } catch (Exception e) {
            logger.error("Keystore initialization ended by exception", e);
        }

    }

    private void _reload_server_cert_temporarily() {
        if (ks.get() == null) {
            return;
        }
        // add all temporary certs to KeyStore (ts)
        for (Certificate cert : CERTS_CACHE) {
            if (cert == null) {
                continue;
            }
            try {
                String name = Utils.X509CertificateSubjectName(cert);
                logger.info("Loaded temporarily certificate: " + name);
                ks.get().setCertificateEntry(name, cert);
            } catch (Exception e) {
                logger.error("Certificate reloading ended by exception", e);
            }
        }
        CERTS_CACHE.clear();

    }

    private void _reload_server_cert_permanently() throws FileNotFoundException {
        if (ks.get() == null) {
            return;
        }

        List<File> files = Utils.getConfigFiles(ssl_certificates_directory, ssl_certificates_suffix, ",");
        Collection<Certificate> certs = null;
        if (Utils.listIsEmpty(files) == true) {
            return;
        }
        for (File file : files) {
            if (file == null) {
                continue;
            }
            String fileName = file.getAbsolutePath();
            try {
                certs = Utils.file2certificates(ssl_certificates_type, fileName);
                if (certs == null) {
                    continue;
                }
                for (Certificate cert : certs) {
                    if (cert == null) {
                        continue;
                    }
                    String name = Utils.X509CertificateSubjectName(cert);
                    logger.info("Loaded permanently certificate: " + name + " with file name: " + fileName);
                    ks.get().setCertificateEntry(name, cert);
                }
            } catch (Exception e) {
                logger.error("Certificate reloading ended by exception", e);
            }

        }
    }

    private void _add_server_cert_permanently(Certificate[] chain) {
        if (chain == null) {
            return;
        }
        String pem_file = null;
        String pem = null;
        for (Certificate cert : chain) {
            if (cert == null) {
                continue;
            }
            pem_file = ssl_trust_store + java.io.File.separator + UUID.randomUUID() + ssl_certificates_suffix;
            try {
                pem = Utils.certificate2string(cert);
                Utils.write(pem_file, pem);
                _log_add_certificate(cert, Utils.permanently, pem_file, pem);
            } catch (Exception e) {
                logger.error("Permanently storing certificates ended with exception", e);
            }
        }

    }

    private void _add_server_cert_temporarily(Certificate[] chain) {
        if (chain == null) {
            return;
        }
        String pem = null;
        for (Certificate cert : chain) {
            if (cert == null) {
                continue;
            }
            try {
                pem = Utils.certificate2string(cert);
                CERTS_CACHE.add(cert);
                _log_add_certificate(cert, Utils.temporarily, Utils.NaN, pem);
            } catch (Exception e) {
                logger.error("Temporarily storing certificates ended with exception", e);
            }
        }

    }

    private void _add_server_cert_manually(Certificate[] chain) {
        if (chain == null) {
            return;
        }
        String pem = null;
        for (Certificate cert : chain) {
            if (cert == null) {
                continue;
            }
            try {
                pem = Utils.certificate2string(cert);
                _log_add_certificate(cert, Utils.manually, Utils.NaN, pem);
            } catch (Exception e) {
                logger.error("Manually storing certificates ended with exception", e);
            }
        }

    }

    private void _add_reload_server_cert(Certificate[] chain) throws NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        switch (ssl_certificates_store) {
            case Utils.temporarily: {
                _add_server_cert_temporarily(chain);
                break;
            }
            case Utils.permanently: {
                _add_server_cert_permanently(chain);
                break;
            }
            case Utils.manually: {
                _add_server_cert_manually(chain);
                return;
            }
            default: {
                return;
            }

        }

        reload();
    }

    private void _log_add_certificate(Certificate cert, String add_type, String pem_file, String pem) {
        String cert_name = Utils.X509CertificateSubjectName(cert);
        String subject = "Added " + add_type + " certificate " + cert_name;
        String msg = "file_name = " + pem_file + Utils.SYSTEM_NEW_LINE + Utils.SYSTEM_NEW_LINE + pem;

        logger.info("----- START -----" + Utils.SYSTEM_NEW_LINE + subject + Utils.SYSTEM_NEW_LINE + msg + Utils.SYSTEM_NEW_LINE + "----- STOP -----");
        notify(subject, msg, Utils.getHostname());
    }

}
