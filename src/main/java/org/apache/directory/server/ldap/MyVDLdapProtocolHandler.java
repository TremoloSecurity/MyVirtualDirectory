package org.apache.directory.server.ldap;

import  org.apache.directory.server.ldap.LdapProtocolHandler;
import org.apache.log4j.Logger;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;

public class MyVDLdapProtocolHandler extends LdapProtocolHandler {

	static Logger logger = Logger.getLogger(MyVDLdapProtocolHandler.class);
	
	MyVDLdapProtocolHandler(LdapServer ldapServer) {
		super(ldapServer);
		
	}

	@Override
	public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
		if (logger.isDebugEnabled()) {
			logger.debug(new StringBuilder().append("Idle timeout reached for '").append(session.getRemoteAddress()).append("', closing").toString());			
		}
		
		session.close(true);
	}

	
}
