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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.apacheds.ApacheDSUtil;
import net.sourceforge.myvd.server.apacheds.MyVDInterceptor;
import net.sourceforge.myvd.server.apacheds.MyVDReferalManager;

import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schemaextractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schemaextractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schemaloader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schemamanager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.ldap.handlers.request.ExtendedRequestHandler;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.server.i18n.I18n;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;


public class Server {
	
	static Logger logger;
	

	public final static String VERSION = "0.9.2";
	
	String configFile;
	Properties props;
	private InsertChain globalChain;
	private Router router;

	private ServerCore serverCore;


	private DefaultDirectoryService directoryService;


	private LdapServer ldapServer;

    
	public InsertChain getGlobalChain() {
		return globalChain;
	}

	public Router getRouter() {
		return router;
	}

	public Server(String configFile) throws FileNotFoundException, IOException {
		this.configFile  = configFile;
		
		
		
		this.props = new Properties();
		
		props.load(new FileInputStream(this.configFile));
		
	}
	
	
	
    /**
     * initialize the schema manager and add the schema partition to diectory service
     *
     * @throws Exception if the schema LDIF files are not found on the classpath
     */
    private void initSchemaPartition() throws Exception
    {
        InstanceLayout instanceLayout = directoryService.getInstanceLayout();
        
        File schemaPartitionDirectory = new File( instanceLayout.getPartitionsDirectory(), "schema" );

        // Extract the schema on disk (a brand new one) and load the registries
        if ( schemaPartitionDirectory.exists() )
        {
            System.out.println( "schema partition already exists, skipping schema extraction" );
        }
        else
        {
            SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( instanceLayout.getPartitionsDirectory() );
            extractor.extractOrCopy();
        }

        SchemaLoader loader = new LdifSchemaLoader( schemaPartitionDirectory );
        SchemaManager schemaManager = new DefaultSchemaManager( loader );

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        List<Throwable> errors = schemaManager.getErrors();

        if ( errors.size() != 0 )
        {
            throw new Exception( I18n.err( I18n.ERR_317, Exceptions.printErrors( errors ) ) );
        }

        directoryService.setSchemaManager( schemaManager );
        
        // Init the LdifPartition with schema
        LdifPartition schemaLdifPartition = new LdifPartition( schemaManager );
        schemaLdifPartition.setPartitionPath( schemaPartitionDirectory.toURI() );

        // The schema partition
        SchemaPartition schemaPartition = new SchemaPartition( schemaManager );
        schemaPartition.setWrappedPartition( schemaLdifPartition );
        directoryService.setSchemaPartition( schemaPartition );
    }
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public void startServer() throws Exception {
		String portString;
		
		
		//this is a hack for testing.
		if (logger == null) {
			getDefaultLog();
		}
		
		this.serverCore = new ServerCore(this.props);
		
		this.serverCore.startService();
		
		this.globalChain = serverCore.getGlobalChain();
		this.router = serverCore.getRouter();
		
		
		String apachedsPath = this.configFile.substring(0,this.configFile.lastIndexOf(File.separator) + 1) + "apacheds-data";
		
		
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
        JdbmPartition systemPartition = new JdbmPartition(directoryService.getSchemaManager());
        systemPartition.setId( "system" );
        systemPartition.setPartitionPath( new File( directoryService.getInstanceLayout().getPartitionsDirectory(), systemPartition.getId() ).toURI() );
        systemPartition.setSuffixDn( new Dn( ServerDNConstants.SYSTEM_DN ) );
        systemPartition.setSchemaManager( directoryService.getSchemaManager() );
        
        // mandatory to call this method to set the system partition
        // Note: this system partition might be removed from trunk
        directoryService.setSystemPartition( systemPartition );
        
        // Disable the ChangeLog system
        directoryService.getChangeLog().setEnabled( false );
        directoryService.setDenormalizeOpAttrsEnabled( true );
        
        String binaryAttributes = this.props.getProperty("server.binaryAttribs","");
		StringTokenizer toker = new StringTokenizer(binaryAttributes);
		
		HashSet<String> binaryAttrs = new HashSet<String>();
		while (toker.hasMoreTokens()) {
			String token = toker.nextToken().toLowerCase();
			binaryAttrs.add(token);
			ApacheDSUtil.addBinaryAttributeToSchema(new DefaultAttribute(token), directoryService.getSchemaManager());
		}
        
        
        List<Interceptor> newlist = new ArrayList<Interceptor>();
        newlist.add(new MyVDInterceptor(globalChain,router,directoryService.getSchemaManager(),binaryAttrs));
        
        directoryService.setInterceptors(newlist);
        
        directoryService.startup();
        
        
        
        
        
        
        this.ldapServer = new LdapServer();
        ldapServer.setDirectoryService(directoryService);
		
        ArrayList<TcpTransport> transports = new ArrayList<TcpTransport>();
        
		portString = props.getProperty("server.listener.port","");
		if (! portString.equals("")) {
			TcpTransport ldapTransport = new TcpTransport(Integer.parseInt(portString));
	        transports.add(ldapTransport);
		}
		
		
        
		portString = props.getProperty("server.secure.listener.port","");
		
		if (! portString.equals("")) {
			String keyStorePath = props.getProperty("server.secure.keystore","");
			
			if (! keyStorePath.startsWith(File.separator)) {
				keyStorePath = this.configFile.substring(0,this.configFile.lastIndexOf(File.separator) + 1) + keyStorePath;
			}
			
			
			logger.debug("Key store : " + keyStorePath);
			
			String keyStorePass = props.getProperty("server.secure.keypass","");
			
			KeyStore keystore;
			try {
				
				ldapServer.setKeystoreFile(keyStorePath);
				ldapServer.setCertificatePassword(keyStorePass);
				
				TcpTransport ldapsTransport = new TcpTransport(Integer.parseInt(portString));
				ldapsTransport.enableSSL(true);
				transports.add(ldapsTransport);
				
			} catch (Throwable t) {
				logger.error("Could not start LDAPS listener",t);
				t.printStackTrace();
			}
		        
		}
		
		Transport[] t = new Transport[transports.size()];
		
		int i=0;
		for (Transport tt : transports) {
			t[i] = tt;
			i++;
		}
		
		long maxSizeLimit = Long.parseLong(props.getProperty("server.listener.maxSizeLimit","0"));
		ldapServer.setMaxSizeLimit(maxSizeLimit);
		
		int maxTimeLimit = Integer.parseInt(props.getProperty("server.listener.maxTimeLimit","0"));
		ldapServer.setMaxTimeLimit(maxTimeLimit);
		
		
		ldapServer.setTransports(t);
        ldapServer.start();
        ((ExtendedRequestHandler) ldapServer.getExtendedRequestHandler()).init(globalChain, router);
		
        
		
		
	}

	private static void getDefaultLog() {
		Properties props = new Properties();
		props.put("log4j.rootLogger", "info,console");
		
		//props.put("log4j.appender.console","org.apache.log4j.RollingFileAppender");
	    //props.put("log4j.appender.console.File","/home/mlb/myvd.log");
		props.put("log4j.appender.console","org.apache.log4j.ConsoleAppender");
		props.put("log4j.appender.console.layout","org.apache.log4j.PatternLayout");
		props.put("log4j.appender.console.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
		
		
		
		PropertyConfigurator.configure(props);
		logger = Logger.getLogger(Server.class.getName());
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
		for (int i=0,m=100;i<m;i++) {
			try {
				LDAPConnection con = new LDAPConnection();
				con.connect("127.0.0.1",Integer.parseInt(props.getProperty("server.listener.port","389")));
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
		
		
		if (System.getProperty("nolog","0").equalsIgnoreCase("0")) {
			String home = args[0];
			home = home.substring(0,home.lastIndexOf(File.separator));
			String loghome = home.substring(0,home.lastIndexOf(File.separator));
			
			Properties props = new Properties();
			
			
			props.load(new FileInputStream(home + "/logging.conf"));
			
			if (! props.containsKey("log4j.rootLogger")) props.put("log4j.rootLogger", "debug,logfile");
			if (! props.containsKey("log4j.appender.logfile")) props.put("log4j.appender.logfile", "org.apache.log4j.RollingFileAppender");
			if (! props.containsKey("log4j.appender.logfile.File")) props.put("log4j.appender.logfile.File",loghome + "/logs/myvd.log");
			if (! props.containsKey("log4j.appender.logfile.MaxFileSize")) props.put("log4j.appender.logfile.MaxFileSize","100KB");
			if (! props.containsKey("log4j.appender.logfile.MaxBackupIndex")) props.put("log4j.appender.logfile.MaxBackupIndex","10");
			if (! props.containsKey("log4j.appender.logfile.layout")) props.put("log4j.appender.logfile.layout","org.apache.log4j.PatternLayout");
			if (! props.containsKey("log4j.appender.logfile.layout.ConversionPattern")) props.put("log4j.appender.logfile.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
			
			
			
			
			
			PropertyConfigurator.configure(props);
			
			Server.logger = Logger.getLogger(Server.class.getName());
		} else {
			getDefaultLog();
		}
		logger.info("MyVirtualDirectory Version : " + Server.VERSION);
		logger.info("Starting MyVirtualDirectory server...");
		try {
			Server server = new Server(args[0]);
			server.startServer();
			logger.info("Server started");
		} catch (Throwable t) {
			logger.error("Error starting server : " + t.toString(),t);
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
