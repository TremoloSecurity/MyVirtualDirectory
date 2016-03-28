/*
 * Copyright 2008 Marc Boorshtein 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package net.sourceforge.myvd.quickstart.util;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpClientError;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.logging.Log; 
import org.apache.commons.logging.LogFactory;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class GetSSLCert {

	public static javax.security.cert.X509Certificate getCert(String host, int port) {
		GetCertSSLProtocolSocketFactory certFactory = new GetCertSSLProtocolSocketFactory();
		Protocol myhttps = new Protocol("https", certFactory, port);
		HttpClient httpclient = new HttpClient();
		httpclient.getHostConfiguration().setHost(host, port, myhttps);
		GetMethod httpget = new GetMethod("/");
		try {
		  httpclient.executeMethod(httpget);
		  //System.out.println(httpget.getStatusLine());
		} catch (Throwable t) {
			//do nothing
		}
		
		finally {
		  httpget.releaseConnection();
		}
		
		return certFactory.getCertificate();
	}
	
	
	public static void main(String[] args) throws Exception {
		javax.security.cert.X509Certificate cert = getCert("test.mydomain.com",636);
		if (cert != null) {
			//System.out.println("Cert DN : " + cert.getIssuerDN());
		} else {
			//System.out.println("No cert");
		}
		
		FileOutputStream fso = new FileOutputStream("/tmp/cert.der");
		fso.write(cert.getEncoded());
		fso.flush();
		fso.close();
	}
	
}

class GetCertSSLProtocolSocketFactory implements SecureProtocolSocketFactory {

	
	javax.security.cert.X509Certificate cert;
	
    /** Log object for this class. */
    private static final Log LOG = LogFactory.getLog(GetCertSSLProtocolSocketFactory.class);

    private SSLContext sslcontext = null;

    /**
     * Constructor for GetCertSSLProtocolSocketFactory.
     */
    public GetCertSSLProtocolSocketFactory() {
        super();
    }

    
    
    private void getCert(SSLSocket socket) throws SSLPeerUnverifiedException {
    	SSLSession session = socket.getSession();
    	 
    	javax.security.cert.X509Certificate[] certs = session.getPeerCertificateChain();
    	
    	if (this.cert == null) {
    		this.cert = certs[certs.length - 1];
    	}
    }
    
    private static SSLContext createEasySSLContext() {
        try {
            SSLContext context = SSLContext.getInstance("SSL");
            context.init(
              null, 
              new TrustManager[] {new EasyX509TrustManager(null)}, 
              null);
            return context;
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new HttpClientError(e.toString());
        }
    }

    private SSLContext getSSLContext() {
        if (this.sslcontext == null) {
            this.sslcontext = createEasySSLContext();
        }
        return this.sslcontext;
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int,java.net.InetAddress,int)
     */
    public Socket createSocket(
        String host,
        int port,
        InetAddress clientHost,
        int clientPort)
        throws IOException, UnknownHostException {

        SSLSocket socket = (SSLSocket) getSSLContext().getSocketFactory().createSocket(
            host,
            port,
            clientHost,
            clientPort
        );
        
        this.getCert(socket);
        
        return socket;
    }

    /**
     * Attempts to get a new socket connection to the given host within the given time limit.
     * <p>
     * To circumvent the limitations of older JREs that do not support connect timeout a 
     * controller thread is executed. The controller thread attempts to create a new socket 
     * within the given limit of time. If socket constructor does not return until the 
     * timeout expires, the controller terminates and throws an {@link ConnectTimeoutException}
     * </p>
     *  
     * @param host the host name/IP
     * @param port the port on the host
     * @param clientHost the local host name/IP to bind the socket to
     * @param clientPort the port on the local machine
     * @param params {@link HttpConnectionParams Http connection parameters}
     * 
     * @return Socket a new socket
     * 
     * @throws IOException if an I/O error occurs while creating the socket
     * @throws UnknownHostException if the IP address of the host cannot be
     * determined
     */
    public Socket createSocket(
        final String host,
        final int port,
        final InetAddress localAddress,
        final int localPort,
        final HttpConnectionParams params
    ) throws IOException, UnknownHostException, ConnectTimeoutException {
        if (params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }
        int timeout = params.getConnectionTimeout();
        SocketFactory socketfactory = getSSLContext().getSocketFactory();
        if (timeout == 0) {
        	
            SSLSocket socket = (SSLSocket) socketfactory.createSocket(host, port, localAddress, localPort);
            this.getCert(socket);
            
            return socket;
        } else {
            Socket socket = socketfactory.createSocket();
            SocketAddress localaddr = new InetSocketAddress(localAddress, localPort);
            SocketAddress remoteaddr = new InetSocketAddress(host, port);
            socket.bind(localaddr);
            socket.connect(remoteaddr, timeout);
            this.getCert((SSLSocket) socket);
            
            
            return socket;
        }
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int)
     */
    public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException {
        SSLSocket socket = (SSLSocket) getSSLContext().getSocketFactory().createSocket(
            host,
            port
        );
        
        this.getCert(socket);
        
        return socket;
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.net.Socket,java.lang.String,int,boolean)
     */
    public Socket createSocket(
        Socket socket,
        String host,
        int port,
        boolean autoClose)
        throws IOException, UnknownHostException {
        SSLSocket socket2 = (SSLSocket) getSSLContext().getSocketFactory().createSocket(
            socket,
            host,
            port,
            autoClose
        );
        
        this.getCert(socket2);
        
        return socket2;
    }

    public boolean equals(Object obj) {
        return ((obj != null) && obj.getClass().equals(GetCertSSLProtocolSocketFactory.class));
    }

    public int hashCode() {
        return GetCertSSLProtocolSocketFactory.class.hashCode();
    }
    
    public javax.security.cert.X509Certificate getCertificate() {
    	return this.cert;
    }

}

class EasyX509TrustManager implements X509TrustManager
{
    private X509TrustManager standardTrustManager = null;

    /** Log object for this class. */
    private static final Log LOG = LogFactory.getLog(EasyX509TrustManager.class);

    /**
     * Constructor for EasyX509TrustManager.
     */
    public EasyX509TrustManager(KeyStore keystore) throws NoSuchAlgorithmException, KeyStoreException {
        super();
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(keystore);
        TrustManager[] trustmanagers = factory.getTrustManagers();
        if (trustmanagers.length == 0) {
            throw new NoSuchAlgorithmException("no trust manager found");
        }
        this.standardTrustManager = (X509TrustManager)trustmanagers[0];
    }

    /**
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(X509Certificate[],String authType)
     */
    public void checkClientTrusted(X509Certificate[] certificates,String authType) throws CertificateException {
        standardTrustManager.checkClientTrusted(certificates,authType);
    }

    /**
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(X509Certificate[],String authType)
     */
    public void checkServerTrusted(X509Certificate[] certificates,String authType) throws CertificateException {
        if ((certificates != null) && LOG.isDebugEnabled()) {
            LOG.debug("Server certificate chain:");
            for (int i = 0; i < certificates.length; i++) {
                LOG.debug("X509Certificate[" + i + "]=" + certificates[i]);
            }
        }
        if ((certificates != null) && (certificates.length == 1)) {
            certificates[0].checkValidity();
        } else {
            standardTrustManager.checkServerTrusted(certificates,authType);
        }
    }

    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    public X509Certificate[] getAcceptedIssuers() {
        return this.standardTrustManager.getAcceptedIssuers();
    }


    
}
