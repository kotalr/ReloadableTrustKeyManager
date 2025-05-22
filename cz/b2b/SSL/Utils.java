/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.b2b.SSL;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 *
 * @author richard
 */
public class Utils {

    public static final String HASH = "#";
    public static final String LINE_SEPARATOR = "line.separator";
    public static final String SYSTEM_NEW_LINE = System.getProperty(LINE_SEPARATOR);
    public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    public static final String off = "off";
    public static final String manually = "manually";
    public static final String temporarily = "temporarily";
    public static final String permanently = "permanently";
    public static final String NaN = "N/A";
    private static final StandardOpenOption[] standardOpenOption = new StandardOpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING};

    private static final Base64.Encoder encoder = Base64.getMimeEncoder(64, SYSTEM_NEW_LINE.getBytes());

    public static boolean listIsEmpty(List in) {
        boolean empty = true;
        if (in == null) {
            return empty;
        }
        if (in.isEmpty() == true) {
            return empty;
        }
        empty = false;
        return empty;

    }

    public static boolean empty(String in) {
        if (in == null) {
            return true;
        }
        if ("".equals(in) == true) {
            return true;
        }

        return false;
    }

    public static String X509CertificateSubjectName(Certificate cert) {
        String subject = null;
        if (cert instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) cert;
            Principal x500Principal = x509Certificate.getSubjectX500Principal();
            if (x500Principal != null) {
                subject = x500Principal.toString();
            }
        }

        return subject;
    }

    public static long X509CertificateNotAfter(Certificate cert) {
        long notafter = -1L;
        if (cert instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) cert;
            Date date = x509Certificate.getNotAfter();
            if (date != null) {
                notafter = date.getTime();
            }
        }

        return notafter;
    }

    public static String X509CertificateIssuerName(Certificate cert) {
        String issuer = null;
        if (cert instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) cert;
            Principal x500Principal = x509Certificate.getIssuerX500Principal();
            if (x500Principal != null) {
                issuer = x500Principal.toString();
            }
        }

        return issuer;
    }

    public static Collection<Certificate> file2certificates(String ssl_certificates_type, String fileName) throws FileNotFoundException, CertificateException, IOException {
        InputStream inStream = null;
        Collection<Certificate> cert = null;
        try {
            inStream = new FileInputStream(fileName);
            CertificateFactory cf = CertificateFactory.getInstance(ssl_certificates_type);
            cert = (Collection<Certificate>) cf.generateCertificates(inStream);
        } finally {
            if (inStream != null) {
                inStream.close();
            }
        }
        return cert;
    }

    public static String certificate2string(Certificate cert) throws CertificateEncodingException {
        String pem = null;

        if (cert == null) {
            return pem;
        }

        pem = HASH + X509CertificateSubjectName(cert) + SYSTEM_NEW_LINE
                + BEGIN_CERTIFICATE + SYSTEM_NEW_LINE
                + encoder.encodeToString(cert.getEncoded()) + SYSTEM_NEW_LINE
                + END_CERTIFICATE + SYSTEM_NEW_LINE;
        return pem;
    }

    public static List<File> getConfigFiles(String dirs, String suffix, String sep) throws FileNotFoundException {
        List<File> result = new ArrayList<>();
        List<File> buffer = null;

        if (empty(dirs) == true) {
            return result;
        }
        String[] aDirs = dirs.split(sep);
        for (String dir : aDirs) {
            if (dir == null) {
                continue;
            }
            buffer = getFileListing(dir.trim(), suffix, false);
            result.addAll(buffer);
        }

        return result;
    }

    public static List<File> getFileListing(String startingDir, String fileFilter, boolean directory) throws FileNotFoundException {
        List<File> out = null;
        File startingDirectory = new File(startingDir);
        validateDirectory(startingDirectory);
        out = getFileListingNoSort(startingDirectory, fileFilter, directory);
        Collections.sort(out);

        return out;
    }

    public static List<File> getFileListingNoSort(File aStartingDir, String fileFilter, boolean directory) throws FileNotFoundException {
        List<File> result = new ArrayList<>();
        File[] filesAndDirs = aStartingDir.listFiles();
        if (filesAndDirs == null) {
            return result;
        }
        for (File file : filesAndDirs) {
            if (file == null) {
                continue;
            }
            if (fileFilter == null || file.getAbsolutePath().toLowerCase().endsWith(fileFilter) == true) {
                if (directory == true) {
                    result.add(file);
                } else {
                    if (file.isFile() == true) {
                        result.add(file);
                    }
                }
            }

            if (file.isDirectory() == true) {
                //must be a directory
                //recursive call!
                List<File> deeperList = getFileListingNoSort(file, fileFilter, directory);
                result.addAll(deeperList);
            }
        }
        return result;
    }

    public static void validateDirectory(File aDirectory) throws FileNotFoundException, IllegalArgumentException {
        if (aDirectory == null) {
            throw new IllegalArgumentException("Directory should not be null.");
        }
        if (!aDirectory.exists()) {
            throw new FileNotFoundException("Directory does not exist: " + aDirectory);
        }
        if (!aDirectory.isDirectory()) {
            throw new IllegalArgumentException("Is not a directory: " + aDirectory);
        }
        if (!aDirectory.canRead()) {
            throw new IllegalArgumentException("Directory cannot be read: " + aDirectory);
        }
    }

    public static boolean write(String fileName, String data) {
        boolean out = false;

        if (empty(fileName) == true) {
            return out;
        }

        try {
            Path path = Paths.get(fileName);
            Files.writeString(path, data, standardOpenOption);
            out = true;
        } catch (IOException e) {
            out = false;
        }
        return out;
    }

    public static String getHostname() {
        String out = null;
        try {
            out = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            out = "";
        }
        return out;
    }

}
