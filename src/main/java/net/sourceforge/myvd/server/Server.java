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
package net.sourceforge.myvd.server;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import net.sf.ehcache.config.CacheConfiguration;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.apacheds.ApacheDSUtil;
import net.sourceforge.myvd.server.apacheds.MyVDInterceptor;
import net.sourceforge.myvd.server.apacheds.MyVDReferalManager;


import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;

import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.DnFactory;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.shared.DefaultDnFactory;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.ldap.LdapServerImpl;
import org.apache.directory.server.ldap.handlers.request.ExtendedRequestHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.log4j.Logger;


public class Server {

    static Logger logger = Logger.getLogger(Server.class);


	public final static String VERSION = "1.0.19";

    String configFile;
    Properties props;
    private InsertChain globalChain;
    private Router router;

    private ServerCore serverCore;

    private DefaultDirectoryService directoryService;

    private LdapServerImpl ldapServer;

    private DnFactory dnFactory;

    public InsertChain getGlobalChain() {
        return globalChain;
    }

    public Router getRouter() {
        return router;
    }
    
    private void integrateIncludes(StringBuffer newConfig, String originalConfig) {
    	
        int begin,end;


        begin = 0;
        end = 0;

        String finalCfg = null;

        begin = originalConfig.indexOf("#[");
        
        while (begin >= 0) {
            if (end == 0) {
                newConfig.append(originalConfig.substring(0,begin));
            } else {
                newConfig.append(originalConfig.substring(end,begin));
            }

            end = originalConfig.indexOf(']',begin + 2);

            String envVarName = originalConfig.substring(begin + 2,end);
            
            
            
            String defaultValue = "";
            if (envVarName.contains(":")) {
            	defaultValue = envVarName.substring(envVarName.indexOf(":") + 1);
            	envVarName = envVarName.substring(0, envVarName.indexOf(":"));
            }
            
            
            String value = System.getenv(envVarName);
            
            

            if (envVarName.equals("all")) {
            	value = "#[all]";
            } else if  (envVarName.equals("entry")) {
            	value = "#[entry]";
            } else if (value == null) {
                value = System.getProperty(envVarName);
            }

            if (value == null) {
            	
                value = defaultValue;
            }
            
            

            if (logger.isDebugEnabled()) {
                logger.debug("Environment Variable '" + envVarName + "'='" + value + "'");
            }

            newConfig.append(value);

            begin = originalConfig.indexOf("#[",end + 1);
            end++;

        }

        if (end != 0) {
            newConfig.append(originalConfig.substring(end));
        } else if (begin == -1 && end == 0) {
        	//nothing found, return original value
        	newConfig.append(originalConfig);
        }

        
    }

    public Server(String configFile) throws FileNotFoundException, IOException {
        this.configFile = configFile;

        String systemProps = System.getProperty("myvd.systemProps");
        if (systemProps != null) {
        	logger.info("Loading system properties from '" + systemProps + "'");
        	Properties sysProps = new Properties();
        	sysProps.load(new FileInputStream(systemProps));
        	
        	for (Object key : sysProps.keySet()) {
        		logger.info("Adding system property '" + key + "'");
        		System.setProperty((String)key, (String)sysProps.get(key));
        	}
        }
        
        
        this.props = new Properties();
        String rawConfig = null;
        try {
			rawConfig = Files.readString(Paths.get(new URI("file://" + this.configFile)));
			StringBuffer newConfig = new StringBuffer();
			integrateIncludes(newConfig,rawConfig);
			rawConfig = newConfig.toString();
		} catch (IOException | URISyntaxException e) {
			logger.error("Couldn't load configuration",e);
			System.exit(1);
		}
        
        
        props.load(new ByteArrayInputStream(rawConfig.getBytes("UTF-8")));

    }

    /**
     * initialize the schema manager and add the schema partition to diectory service
     *
     * @throws Exception if the schema LDIF files are not found on the classpath
     */
    private void initSchemaPartition() throws Exception {
        InstanceLayout instanceLayout = directoryService.getInstanceLayout();

        File schemaPartitionDirectory = new File(instanceLayout.getPartitionsDirectory(), "schema");

        // Extract the schema on disk (a brand new one) and load the registries
        if (schemaPartitionDirectory.exists()) {
            System.out.println("schema partition already exists, skipping schema extraction");
        } else {
            SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor(instanceLayout.getPartitionsDirectory());
            extractor.extractOrCopy();
        }

        SchemaLoader loader = new LdifSchemaLoader(schemaPartitionDirectory);
        SchemaManager schemaManager = new DefaultSchemaManager(loader);

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        List<Throwable> errors = schemaManager.getErrors();

        if (errors.size() != 0) {
            throw new Exception(I18n.err(I18n.ERR_317, Exceptions.printErrors(errors)));
        }

        directoryService.setSchemaManager(schemaManager);

        if (this.dnFactory == null) {
            this.dnFactory = new DefaultDnFactory(schemaManager,  10000);
        }

        // Init the LdifPartition with schema
        LdifPartition schemaLdifPartition = new LdifPartition(schemaManager, this.dnFactory);
        schemaLdifPartition.setPartitionPath(schemaPartitionDirectory.toURI());

        // The schema partition
        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(schemaLdifPartition);
        directoryService.setSchemaPartition(schemaPartition);
    }

    private void deleteDir(File d) {
        if (d.isDirectory()) {
            File[] subs = d.listFiles();
            for (File f : subs) {
                deleteDir(f);
            }

            if (!d.delete()) {
                logger.error("Could not delete directory : '" + d.getAbsolutePath() + "'");
            }
        } else {
            if (!d.delete()) {
                logger.error("Could not delete file : '" + d.getAbsolutePath() + "'");
            }
        }
    }

    public void startServer() throws Exception {
        String portString;



        String apachedsPath = this.configFile.substring(0, this.configFile.lastIndexOf(File.separator) + 1) + "apacheds-data";

        logger.info("ApacheDS System Directory Path : '" + apachedsPath + "'");

        File cfgPath = new File(apachedsPath);

        if (cfgPath.isDirectory()) {
            logger.warn("ApacheDS system partition exists, deleting to clear it out");
            this.deleteDir(cfgPath);
        }

        this.serverCore = new ServerCore(this.props);

        this.serverCore.startService();

        this.globalChain = serverCore.getGlobalChain();
        this.router = serverCore.getRouter();

        this.directoryService = new DefaultDirectoryService();
        directoryService.setShutdownHookEnabled(false);
        directoryService.setAccessControlEnabled(false);
        directoryService.setAllowAnonymousAccess(true);
        directoryService.setInstanceLayout(new InstanceLayout(new File(apachedsPath)));
        directoryService.setReferralManager(new MyVDReferalManager());

        // first load the schema
        initSchemaPartition();

        // then the system partition
        // this is a MANDATORY partition
        // DO NOT add this via addPartition() method, trunk code complains about duplicate partition
        // while initializing 
        JdbmPartition systemPartition = new JdbmPartition(directoryService.getSchemaManager(), this.dnFactory);
        systemPartition.setId("system");
        systemPartition.setPartitionPath(new File(directoryService.getInstanceLayout().getPartitionsDirectory(), systemPartition.getId()).toURI());
        systemPartition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
        systemPartition.setSchemaManager(directoryService.getSchemaManager());

        // mandatory to call this method to set the system partition
        // Note: this system partition might be removed from trunk
        directoryService.setSystemPartition(systemPartition);
        
        // create a catch-all partition
        JdbmPartition catchAll = new JdbmPartition(directoryService.getSchemaManager(), this.dnFactory);
        catchAll.setId("all");
        catchAll.setPartitionPath(new File(directoryService.getInstanceLayout().getPartitionsDirectory(), catchAll.getId()).toURI());
        catchAll.setSuffixDn(new Dn("cn=doesnotmatter"));
        catchAll.setSchemaManager(directoryService.getSchemaManager());
        directoryService.addPartition(catchAll);

        // Disable the ChangeLog system
        directoryService.getChangeLog().setEnabled(false);
        directoryService.setDenormalizeOpAttrsEnabled(true);

        String binaryAttributes = this.props.getProperty("server.binaryAttribs", "");
        StringTokenizer toker = new StringTokenizer(binaryAttributes);

        HashSet<String> binaryAttrs = new HashSet<String>();
        while (toker.hasMoreTokens()) {
            String token = toker.nextToken().toLowerCase();
            binaryAttrs.add(token);
            ApacheDSUtil.addBinaryAttributeToSchema(new DefaultAttribute(token), directoryService.getSchemaManager());
        }

        List<Interceptor> newlist = new ArrayList<Interceptor>();
        newlist.add(new MyVDInterceptor(globalChain, router, directoryService.getSchemaManager(), binaryAttrs));

        directoryService.setInterceptors(newlist);

        directoryService.startup();

        this.ldapServer = new LdapServerImpl();
        ldapServer.setDirectoryService(directoryService);

        String authRequiredString = props.getProperty("server.listener.authRequired", "false").trim();
        ldapServer.setAuthRequired(Boolean.valueOf(authRequiredString));

        ArrayList<TcpTransport> transports = new ArrayList<TcpTransport>();

        portString = props.getProperty("server.listener.port", "").trim();
        if (!portString.equals("")) {
            String host = props.getProperty("server.listener.host", "").trim();

            TcpTransport ldapTransport = host.equals("")
                                         ? new TcpTransport(Integer.parseInt(portString))
                                         : new TcpTransport(host, Integer.parseInt(portString));
            ldapTransport.setNeedClientAuth(true);
            

            String idleTimeoutSeconds = props.getProperty("server.listener.idleTimeoutSeconds");
            if (idleTimeoutSeconds != null) {
            	//ldapTransport.getAcceptor().addListener(new IdleIoServiceListener(Long.parseLong(idleTimeoutMillis)));
            	ldapTransport.getAcceptor().getSessionConfig().setBothIdleTime(Integer.parseInt(idleTimeoutSeconds));
            }
            transports.add(ldapTransport);
        }

        portString = props.getProperty("server.secure.listener.port", "").trim();

        if (!portString.equals("")) {
            String keyStorePath = props.getProperty("server.secure.keystore", "").trim();

            if (!keyStorePath.startsWith(File.separator)) {
                keyStorePath = this.configFile.substring(0, this.configFile.lastIndexOf(File.separator) + 1) + keyStorePath;
            }

            logger.debug("Key store : " + keyStorePath);

            String keyStorePass = props.getProperty("server.secure.keypass", "");

            String clientMode = props.getProperty("server.secure.clientmode", "none");

            ArrayList<String> allowedNames = new ArrayList<String>();
            String allowedNamesStr = props.getProperty("server.secure.allowedAliases", "");
            toker = new StringTokenizer(allowedNamesStr, ",", false);

            while (toker.hasMoreTokens()) {
                allowedNames.add(toker.nextToken());
            }

            KeyStore keystore;
            try {
                if (clientMode.equalsIgnoreCase("want")) {
                    ldapServer.setTlsWantClientAuth(true);
                }

                if (clientMode.equalsIgnoreCase("need")) {
                    ldapServer.setTlsNeedClientAuth(true);
                }

                ldapServer.setTlsAllowedNames(allowedNames);

                String keyAlias = props.getProperty("server.secure.alias");
                if (keyAlias != null) {
                    ldapServer.setTlsKeyAlias(keyAlias);
                }
                
                ldapServer.setKeystoreFile(keyStorePath);
                ldapServer.setCertificatePassword(keyStorePass);
                

                TcpTransport ldapsTransport = new TcpTransport(Integer.parseInt(portString));
                ldapsTransport.enableSSL(true);

                if (clientMode.equalsIgnoreCase("want")) {
                    ldapsTransport.setWantClientAuth(true);
                }

                if (clientMode.equalsIgnoreCase("need")) {
                    ldapsTransport.setNeedClientAuth(true);
                }
                

                
                String idleTimeoutSeconds = props.getProperty("server.secure.idleTimeoutSeconds");
                if (idleTimeoutSeconds != null) {
                	//ldapTransport.getAcceptor().addListener(new IdleIoServiceListener(Long.parseLong(idleTimeoutMillis)));
                	ldapsTransport.getAcceptor().getSessionConfig().setBothIdleTime(Integer.parseInt(idleTimeoutSeconds));

                }

                transports.add(ldapsTransport);

            } catch (Throwable t) {
                logger.error("Could not start LDAPS listener", t);
                t.printStackTrace();
            }

        }

        Transport[] t = new Transport[transports.size()];

        int i = 0;
        for (Transport tt : transports) {
            t[i] = tt;
            i++;
        }

        long maxSizeLimit = Long.parseLong(props.getProperty("server.listener.maxSizeLimit", "0"));
        ldapServer.setMaxSizeLimit(maxSizeLimit);

        int maxTimeLimit = Integer.parseInt(props.getProperty("server.listener.maxTimeLimit", "0"));
        ldapServer.setMaxTimeLimit(maxTimeLimit);

        ldapServer.setTransports(t);
        ldapServer.start();
        ((ExtendedRequestHandler) ldapServer.getExtendedRequestHandler()).init(globalChain, router);

        final int shutdownPort = Integer.parseInt(props.getProperty("server.shutdown.port", "-1"));
        if (shutdownPort > 0) {
            final String shutdownHost = props.getProperty("server.shutdown.host", "127.0.0.1");
            final String shutdownCommand = props.getProperty("server.shutdown.command", "shutdown");

            final Server server = this;

            new Thread() {
                public void run() {
                    logger.info("Starting shutdown socket listener");
                    try {
                        ServerSocket socket = new ServerSocket(shutdownPort, 0, InetAddress.getByName(shutdownHost));
                        while (true) {
                            logger.info("shutdown waiting for input");
                            Socket clientSocket = null;
                            try {
                                clientSocket = socket.accept();
                            } catch (Throwable t) {
                                logger.warn("Could not accept connection", t);
                                continue;
                            }
                            logger.info("request received");
                            //PrintWriter out =
                            //    new PrintWriter(clientSocket.getOutputStream(), true);
                            BufferedReader in = new BufferedReader(
                                    new InputStreamReader(clientSocket.getInputStream()));
                            logger.info("reading data");
                            String command = in.readLine();
                            logger.info("'" + command + "'");
                            if (command != null) {
                                command.trim();
                            }
                            logger.info("'" + command + "'");
                            if (shutdownCommand.equalsIgnoreCase(command)) {
                                logger.info("Stopping threads");

                                try {
                                    server.stopServer();
                                } catch (Exception e1) {
                                    logger.warn("Could not gracefully shutdown server", e1);
                                }

                                logger.info("Closing input stream");

                                try {
                                    in.close();
                                } catch (Throwable t) {
                                }

								/*try {
                                    out.close();
								} catch (Throwable t) {}*/

                                logger.info("Closing client socket");
                                try {
                                    clientSocket.close();
                                } catch (Throwable t) {
                                }

                                logger.info("Closing server socket");
                                try {
                                    socket.close();
                                } catch (Throwable t) {
                                }

                                logger.info("Sleeping for 10 seconds");
                                try {
                                    Thread.sleep(10000);
                                    logger.info("Exiting");
                                    System.exit(0);
                                    return;
                                } catch (Exception e) {
                                }

                            } else {
                                command = null;
                                logger.info("invalid command");
                                try {
                                    in.close();
                                } catch (Throwable t) {
                                }

								/*try {
									out.close();
								} catch (Throwable t) {}
*/
                                try {
                                    clientSocket.close();
                                } catch (Throwable t) {
                                }

                            }
                        }
                    } catch (IOException e) {
                        logger.error("Could not start shutdown listener", e);
                    }
                }
            }.start();
        }

    }



	/*private void startLDAP(String portString,IoFilterChainBuilder chainBuilder) throws LdapNamingException, IOException {
		if (! portString.equals("")) {
			logger.debug("Starting server on port : " + portString);
			
			LdapProtocolProvider protocolProvider = new LdapProtocolProvider(this.globalChain,this.router,this.props.getProperty("server.binaryAttribs","userPassword"));
			
//			 Disable the disconnection of the clients on unbind
            SocketAcceptorConfig acceptorCfg = new SocketAcceptorConfig();
            acceptorCfg.setDisconnectOnUnbind( false );
            
            acceptorCfg.setReuseAddress( true );
            
            if (chainBuilder == null) {
            	acceptorCfg.setFilterChainBuilder( new DefaultIoFilterChainBuilder() );
            } else {
            	acceptorCfg.setFilterChainBuilder( chainBuilder );
            }
            acceptorCfg.setThreadModel( threadModel );
            //acceptorCfg.getFilterChain().addLast("codec", new ProtocolCodecFilter( new TextLineCodecFactory( Charset.forName( "UTF-8" ))));
            
            ((SocketSessionConfig)(acceptorCfg.getSessionConfig())).setTcpNoDelay( true );
            
            logger.debug("Port String : " + portString);
            logger.debug("Protocol Prpvider : " + protocolProvider);
            logger.debug("AcceptorConfig : " + acceptorCfg);
            logger.debug("tcpAcceptor : " + tcpAcceptor);
            
            //tcpAcceptor = new SocketAcceptor(((int) Runtime.getRuntime().availableProcessors()) + 1,null);
            tcpAcceptor = new SocketAcceptor();
            
            //try 3 times?
            for (int i=0;i<3;i++) {
            	try {
            		tcpAcceptor.bind( new InetSocketAddress( Integer.parseInt(portString) ), protocolProvider.getHandler(), acceptorCfg );
            		break;
            	} catch (java.net.BindException e) {
            		logger.error("Could not bind to address, waiting 30 seconds to try again",e);
            		try {
						Thread.sleep(30000);
					} catch (InterruptedException e1) {
						
					}
            	}
            }
            
			
			minaRegistry = new SimpleServiceRegistry();
			Service service = new Service( "ldap", TransportType.SOCKET, new InetSocketAddress( Integer.parseInt(portString) ) );
			
			logger.debug("LDAP listener started");
		}
	}*/

    public void stopServer() throws Exception {
        //this.minaRegistry.unbindAll();
        logger.info("Shutting down server");
        this.ldapServer.stop();
        this.directoryService.shutdown();

        //this.stopLDAP0(Integer.parseInt(props.getProperty("server.listener.port","389")));
        for (int i = 0, m = 100; i < m; i++) {
            try {
                LDAPConnection con = new LDAPConnection();
                con.connect("127.0.0.1", Integer.parseInt(props.getProperty("server.listener.port", "389")));
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {

                }
            } catch (LDAPException e) {
                //logger.error("Error",e);
                break;
            }
        }

        this.router.shutDownRouter();

        logger.info("Server Stopped");
    }

    public static void main(String[] args) throws Exception {

        

        logger.info("MyVirtualDirectory Version : " + Server.VERSION);
        logger.info("Starting MyVirtualDirectory server...");
        try {
            Server server = new Server(args[0]);
            server.startServer();
            logger.info("Server started");
        } catch (Throwable t) {
            logger.error("Error starting server : " + t.toString(), t);
        }

    }

    private Properties getProps() {
        return this.props;
    }
	
	/*private void stopLDAP0( int port )
    {
        try
        {
            // we should unbind the service before we begin sending the notice 
            // of disconnect so new connections are not formed while we process
            List writeFutures = new ArrayList();

            // If the socket has already been unbound as with a successful 
            // GracefulShutdownRequest then this will complain that the service
            // is not bound - this is ok because the GracefulShutdown has already
            // sent notices to to the existing active sessions
            List sessions = null;
            try
            {
                sessions = new ArrayList( tcpAcceptor.getManagedSessions( new InetSocketAddress( port ) ) );
            }
            catch ( IllegalArgumentException e )
            {
                logger.warn( "Seems like the LDAP service (" + port + ") has already been unbound." );
                return;
            }

            tcpAcceptor.unbind( new InetSocketAddress( port ) );
            if ( logger.isInfoEnabled() )
            {
            	logger.info( "Unbind of an LDAP service (" + port + ") is complete." );
            	logger.info( "Sending notice of disconnect to existing clients sessions." );
            }

            // Send Notification of Disconnection messages to all connected clients.
            if ( sessions != null )
            {
                for ( Iterator i = sessions.iterator(); i.hasNext(); )
                {
                    IoSession session = ( IoSession ) i.next();
                    writeFutures.add( session.write( NoticeOfDisconnect.UNAVAILABLE ) );
                }
            }

            // And close the connections when the NoDs are sent.
            Iterator sessionIt = sessions.iterator();
            for ( Iterator i = writeFutures.iterator(); i.hasNext(); )
            {
                WriteFuture future = ( WriteFuture ) i.next();
                future.join( 1000 );
                ( ( IoSession ) sessionIt.next() ).close();
            }
        }
        catch ( Exception e )
        {
        	logger.warn( "Failed to sent NoD.", e );
        }
        
        try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			
		}
        
    }*/

}
