# ReloadableTrustKeyManager

Reloadable Java X509 TrustManager (PEM) and KeyManager (PKCS12)

Implementation of an automatically renewing java TrustManager from X509 pem certificate formats and an automatically renewing KeyManager from pkcs12 format.

TrustManager is refreshed whenever the system obtains an unknown certificate.
The KeyManager is refreshed whenever a key is about to expire.



Examples (simplified) of usage:

```

 String ssl_certificates_directory="/tmp/x509/cert"; //Directory with stored certificates to be loaded.
 String ssl_certificates_suffix=".crt"; //Certificate file extension.
 String ssl_certificates_store="permanently"; //Type of storage for new certificates. (off,manually,temporarily,permanently) - see java code
 String ssl_certificates_type="X.509"; //Type of stored certificates.
 String ssl_trust_store="/tmp/x509/cert/automatic"; //Directory for permanent storage of new certificates.

 String ssl_key_file="/tmp/x509/key/mykey.p12"; //Private key and certificate file in pkcs12 format.
 String ssl_key_password="YOURPASSWORD"; //File password.
 long ssl_key_store_reload_ms=86400000; //It means renew 24 hours before the key expires.

 String ssl_protocol="SSLv3";
 String hostname="YOURSERVER";

 ReloadableX509TrustManager reloadableX509TrustManager = new ReloadableX509TrustManager(ssl_certificates_directory, ssl_certificates_suffix, ssl_certificates_store, ssl_certificates_type, ssl_trust_store);
 ReloadablePKCS12KeyManager reloadablePKCS12KeyManager = new ReloadablePKCS12KeyManager(ssl_key_file, ssl_key_password, ssl_key_store_reload_ms);
 TrustManager[] tms = new TrustManager[]{reloadableX509TrustManager};
 KeyManager[] kms = new KeyManager[]{reloadablePKCS12KeyManager};
 SSLContext sslContext = SSLContext.getInstance(ssl_protocol);
 sslContext.init(kms, tms, null);


 ServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
 ServerSocket serverSocket = serverSocketFactory.createServerSocket(2083, 50);

 SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
 SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(InetAddress.getByName(hostname), 2083);

```
