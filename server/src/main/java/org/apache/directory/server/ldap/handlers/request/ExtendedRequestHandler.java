/*
*  Licensed to the Apache Software Foundation (ASF) under one
*  or more contributor license agreements.  See the NOTICE file
*  distributed with this work for additional information
*  regarding copyright ownership.  The ASF licenses this file
*  to you under the Apache License, Version 2.0 (the
*  "License"); you may not use this file except in compliance
*  with the License.  You may obtain a copy of the License at
*  
*    http://www.apache.org/licenses/LICENSE-2.0
*  
*  Unless required by applicable law or agreed to in writing,
*  software distributed under the License is distributed on an
*  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*  KIND, either express or implied.  See the License for the
*  specific language governing permissions and limitations
*  under the License. 
*  
*/
package org.apache.directory.server.ldap.handlers.request;


import java.util.ArrayList;
import java.util.HashMap;

import net.sourceforge.myvd.chain.ExetendedOperationInterceptorChain;
import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.types.DistinguishedName;
import net.sourceforge.myvd.types.ExtendedOperation;
import net.sourceforge.myvd.types.Password;
import net.sourceforge.myvd.types.SessionVariables;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.server.ldap.ExtendedOperationHandler;
import org.apache.directory.server.ldap.LdapSession;
import org.apache.directory.server.ldap.handlers.LdapRequestHandler;

import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPExtendedOperation;


/**
* A single reply MessageReceived handler for {@link ExtendedRequest}s.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ExtendedRequestHandler extends LdapRequestHandler<ExtendedRequest<ExtendedResponse>>
{
	
	
	private InsertChain globalChain;
	private Router router;
	
	public void init(InsertChain globalChain,Router router) {
		this.globalChain = globalChain;
		this.router = router;
	}
	
    /**
     * {@inheritDoc}
     */
    public void handle( LdapSession session, ExtendedRequest<ExtendedResponse> req ) throws Exception
    {
        /*ExtendedOperationHandler<ExtendedRequest<ExtendedResponse>, ExtendedResponse> handler = getLdapServer()
            .getExtendedOperationHandler( req.getRequestName() );

        if ( handler == null )
        {
            // As long as no extended operations are implemented, send appropriate
            // error back to the client.
            String msg = "Unrecognized extended operation EXTENSION_OID: " + req.getRequestName();
            LdapResult result = req.getResultResponse().getLdapResult();
            result.setResultCode( ResultCodeEnum.PROTOCOL_ERROR );
            result.setDiagnosticMessage( msg );
            session.getIoSession().write( req.getResultResponse() );
            return;
        }*/

        try
        {
        	HashMap<Object,Object> userRequest = new HashMap<Object,Object>();
    		
    		//how to track?
    		HashMap<Object,Object> userSession = session.getCoreSession().getUserSession();
    		if (userSession.get(SessionVariables.BOUND_INTERCEPTORS) == null) {
    			userSession.put(SessionVariables.BOUND_INTERCEPTORS,new ArrayList<String>());
    		}
    		
    		DistinguishedName bindDN;
    		byte[] password;
    		
    		if (session.getCoreSession().isAnonymous()) {
    			bindDN = new DistinguishedName("");
    			password = null;
    		} else {
    			bindDN = new DistinguishedName(session.getCoreSession().getAuthenticatedPrincipal().getDn().getName());
    			if (session.getCoreSession().getAuthenticatedPrincipal().getUserPasswords() != null) {
    				password = session.getCoreSession().getAuthenticatedPrincipal().getUserPasswords()[0];
    			} else {
    				password = null;
    			}
    		}
    		
    		Password pass = new Password(password);
        	
    		
    		
        	ExetendedOperationInterceptorChain chain = new ExetendedOperationInterceptorChain(bindDN,pass,0,this.globalChain,userSession,userRequest,router);
            
            ExtendedOperation op = new ExtendedOperation(null, new LDAPExtendedOperation(req.getRequestName(),((ExtendedRequestDecorator) req).getRequestValue()));
            chain.nextExtendedOperations(op,new LDAPConstraints());
            
            LdapResult result = req.getResultResponse().getLdapResult();
            result.setResultCode( ResultCodeEnum.SUCCESS );
            
            session.getIoSession().write( req.getResultResponse() );
            
            
        }
        catch ( Exception e )
        {
            LdapResult result = req.getResultResponse().getLdapResult();
            result.setResultCode( ResultCodeEnum.OTHER );
            result.setDiagnosticMessage( ResultCodeEnum.OTHER
                + ": Extended operation handler for the specified EXTENSION_OID (" + req.getRequestName()
                + ") has failed to process your request:\n" + ExceptionUtils.getStackTrace( e ) );
            ExtendedResponse resp = req.getResultResponse();
            session.getIoSession().write( resp );
        }
    }
}