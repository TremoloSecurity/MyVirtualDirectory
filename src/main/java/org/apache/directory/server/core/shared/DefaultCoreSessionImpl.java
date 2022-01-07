/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.server.core.shared;


import java.io.File;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import jdbm.recman.BaseRecordManager;

import org.apache.directory.api.ldap.extras.controls.syncrepl.syncRequest.SyncRequestValue;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.Cursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EmptyCursor;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.UnbindRequest;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.SortResponseImpl;
import org.apache.directory.api.ldap.model.message.controls.SortResultCode;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.OperationManager;
import org.apache.directory.server.core.api.changelog.LogChange;
import org.apache.directory.server.core.api.interceptor.context.AbstractOperationContext;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.CompareOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveAndRenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveOperationContext;
import org.apache.directory.server.core.api.interceptor.context.OperationContext;
import org.apache.directory.server.core.api.interceptor.context.RenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.interceptor.context.UnbindOperationContext;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.partition.PartitionTxn;
import org.apache.directory.server.i18n.I18n;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The default CoreSession implementation.
 * 
 * TODO - has not been completed yet
 * TODO - need to supply controls and other parameters to setup opContexts
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultCoreSessionImpl implements CoreSession, DefaultCoreSession
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultCoreSessionImpl.class );

    /** The DirectoryService we are connected to */
    private final DirectoryService directoryService;

    /** The Principal used to process operations */
    private final LdapPrincipal authenticatedPrincipal;

    /** The anonymous principal, if we have to process operation as anonymous */
    private final LdapPrincipal anonymousPrincipal;

    /** The authorized principal, which will be used when a user has been authorized */
    private LdapPrincipal authorizedPrincipal;

    /** A reference to the ObjectClass AT */
    protected AttributeType objectClassAT;

    /** The associated IoSession */
    private IoSession ioSession;

    /** flag to indicate if the password must be changed */
    private boolean pwdMustChange;

    /** A flag set when the startTransaction extended operation has been received */
    private boolean hasSessionTransaction;
    
    /** The Map containing the transactions associated with each partition */
    private Map<String, PartitionTxn> transactionMap = new HashMap<>();
    
    /** The transaction ID */
    private AtomicLong transactionId = new AtomicLong( 0 );

    /** The user's session for arbitrary data */
    private HashMap<Object,Object> userSession;

    /**
     * Creates a new instance of a DefaultCoreSession
     * @param principal The principal to use to process operation for this session
     * @param directoryService The DirectoryService to which we will send requests
     */
    public DefaultCoreSessionImpl( LdapPrincipal principal, DirectoryService directoryService )
    {
        this.directoryService = directoryService;
        authenticatedPrincipal = principal;

        if ( principal.getAuthenticationLevel() == AuthenticationLevel.NONE )
        {
            anonymousPrincipal = principal;
        }
        else
        {
            anonymousPrincipal = new LdapPrincipal( directoryService.getSchemaManager() );
        }

        // setup attribute type value
        objectClassAT = directoryService.getSchemaManager().getAttributeType( SchemaConstants.OBJECT_CLASS_AT );

        // initalize the user session
        this.userSession = new HashMap<Object,Object>();
    }


    /**
     * Gets the IoSession from the CoreSession. This is only useful when the server is not embedded.
     * 
     * @return ioSession The IoSession for this CoreSession
     */
    @Override
	public IoSession getIoSession()
    {
        return ioSession;
    }


    /**
     * Stores the IoSession into the CoreSession. This is only useful when the server is not embedded.
     * 
     * @param ioSession The IoSession for this CoreSession
     */
    @Override
	public void setIoSession( IoSession ioSession )
    {
        this.ioSession = ioSession;
        HashMap<Object,Object> lsession = (HashMap<Object, Object>) ioSession.getAttribute("MYVD_USER_SESSION");
        if (lsession != null) {
        	this.userSession = lsession;
        }
    }


    /**
     * Set the ignoreRefferal flag for the current operationContext.
     *
     * @param opContext The current operationContext
     * @param ignoreReferral The flag
     */
    private void setReferralHandling( AbstractOperationContext opContext, boolean ignoreReferral )
    {
        if ( ignoreReferral )
        {
            opContext.ignoreReferral();
        }
        else
        {
            opContext.throwReferral();
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( Entry entry ) throws LdapException
    {
        add( entry, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( Entry entry, boolean ignoreReferral ) throws LdapException
    {
        add( entry, ignoreReferral, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( Entry entry, LogChange log ) throws LdapException
    {
        AddOperationContext addContext = new AddOperationContext( this, entry );

        addContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.add( addContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( Entry entry, boolean ignoreReferral, LogChange log ) throws LdapException
    {
        AddOperationContext addContext = new AddOperationContext( this, entry );

        addContext.setLogChange( log );
        setReferralHandling( addContext, ignoreReferral );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.add( addContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( AddRequest addRequest ) throws LdapException
    {
        add( addRequest, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( AddRequest addRequest, LogChange log ) throws LdapException
    {
        AddOperationContext addContext = new AddOperationContext( this, addRequest );

        addContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        
        try
        {
            operationManager.add( addContext );
        }
        catch ( LdapException e )
        {
            addRequest.getResultResponse().addAllControls( addContext.getResponseControls() );
            throw e;
        }
        
        addRequest.getResultResponse().addAllControls( addContext.getResponseControls() );
    }


    private Value convertToValue( String oid, Object value ) throws LdapException
    {
        Value val;

        AttributeType attributeType = directoryService.getSchemaManager().lookupAttributeTypeRegistry( oid );

        // make sure we add the request controls to operation
        if ( attributeType.getSyntax().isHumanReadable() )
        {
            if ( value instanceof String )
            {
                val = new Value( attributeType, ( String ) value );
            }
            else if ( value instanceof byte[] )
            {
                val = new Value( attributeType, Strings.utf8ToString( ( byte[] ) value ) );
            }
            else
            {
                throw new LdapException( I18n.err( I18n.ERR_309, oid ) );
            }
        }
        else
        {
            if ( value instanceof String )
            {
                val = new Value( attributeType, Strings.getBytesUtf8( ( String ) value ) );
            }
            else if ( value instanceof byte[] )
            {
                val = new Value( attributeType, ( byte[] ) value );
            }
            else
            {
                throw new LdapException( I18n.err( I18n.ERR_309, oid ) );
            }
        }

        return val;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String oid, Object value ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();

        return operationManager.compare( new CompareOperationContext( this, dn, oid, convertToValue( oid, value ) ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String oid, Object value, boolean ignoreReferral ) throws LdapException
    {
        CompareOperationContext compareContext = new CompareOperationContext( this, dn, oid,
            convertToValue( oid, value ) );

        setReferralHandling( compareContext, ignoreReferral );

        OperationManager operationManager = directoryService.getOperationManager();
        return operationManager.compare( compareContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( Dn dn ) throws LdapException
    {
        delete( dn, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( Dn dn, LogChange log ) throws LdapException
    {
        DeleteOperationContext deleteContext = new DeleteOperationContext( this, dn );

        deleteContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.delete( deleteContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( Dn dn, boolean ignoreReferral ) throws LdapException
    {
        delete( dn, ignoreReferral, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( Dn dn, boolean ignoreReferral, LogChange log ) throws LdapException
    {
        DeleteOperationContext deleteContext = new DeleteOperationContext( this, dn );

        deleteContext.setLogChange( log );
        setReferralHandling( deleteContext, ignoreReferral );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.delete( deleteContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapPrincipal getAnonymousPrincipal()
    {
        return anonymousPrincipal;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapPrincipal getAuthenticatedPrincipal()
    {
        return authenticatedPrincipal;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticationLevel getAuthenticationLevel()
    {
        return getEffectivePrincipal().getAuthenticationLevel();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getClientAddress()
    {
        if ( ioSession != null )
        {
            return ioSession.getRemoteAddress();
        }
        else
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<Control> getControls()
    {
        // TODO Auto-generated method stub
        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DirectoryService getDirectoryService()
    {
        return directoryService;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapPrincipal getEffectivePrincipal()
    {
        if ( authorizedPrincipal == null )
        {
            return authenticatedPrincipal;
        }

        return authorizedPrincipal;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<OperationContext> getOutstandingOperations()
    {
        // TODO Auto-generated method stub
        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SocketAddress getServiceAddress()
    {
        if ( ioSession != null )
        {
            return ioSession.getServiceAddress();
        }
        else
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isConfidential()
    {
        // TODO Auto-generated method stub
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVirtual()
    {
        // TODO Auto-generated method stub
        return true;
    }


    /**
     * TODO - perhaps we should just use a flag that is calculated on creation
     * of this session
     * 
     * @see org.apache.directory.server.core.api.CoreSession#isAdministrator()
     */
    @Override
    public boolean isAdministrator()
    {
        String normName = getEffectivePrincipal().getName();

        return normName.equals( ServerDNConstants.ADMIN_SYSTEM_DN_NORMALIZED );
    }


    /**
     * TODO - this method impl does not check to see if the principal is in
     * the administrators group - it only returns true of the principal is
     * the actual admin user.  need to make it check groups.
     * 
     * TODO - perhaps we should just use a flag that is calculated on creation
     * of this session
     * 
     * @see org.apache.directory.server.core.api.CoreSession#isAnAdministrator()
     */
    @Override
    public boolean isAnAdministrator()
    {
        if ( isAdministrator() )
        {
            return true;
        }

        // TODO fix this so it checks groups
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cursor<Entry> list( Dn dn, AliasDerefMode aliasDerefMode,
        String... returningAttributes ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();

        PresenceNode filter = new PresenceNode( objectClassAT );
        SearchOperationContext searchContext = new SearchOperationContext( this, dn, SearchScope.ONELEVEL, filter,
            returningAttributes );
        searchContext.setAliasDerefMode( aliasDerefMode );

        return operationManager.search( searchContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn, String... attrIds ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();
        LookupOperationContext lookupContext = new LookupOperationContext( this, dn, attrIds );

        return operationManager.lookup( lookupContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn, Control[] controls, String... attrIds ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();
        LookupOperationContext lookupContext = new LookupOperationContext( this, dn, attrIds );

        if ( controls != null )
        {
            lookupContext.addRequestControls( controls );
        }

        return operationManager.lookup( lookupContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, Modification... mods ) throws LdapException
    {
        modify( dn, Arrays.asList( mods ), LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, List<Modification> mods ) throws LdapException
    {
        modify( dn, mods, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, List<Modification> mods, LogChange log ) throws LdapException
    {
        if ( mods == null )
        {
            return;
        }

        List<Modification> serverModifications = new ArrayList<>( mods.size() );

        for ( Modification mod : mods )
        {
            serverModifications.add( new DefaultModification( directoryService.getSchemaManager(), mod ) );
        }

        ModifyOperationContext modifyContext = new ModifyOperationContext( this, dn, serverModifications );

        modifyContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        
        operationManager.modify( modifyContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, List<Modification> mods, boolean ignoreReferral ) throws LdapException
    {
        modify( dn, mods, ignoreReferral, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, List<Modification> mods, boolean ignoreReferral, LogChange log ) throws LdapException
    {
        if ( mods == null )
        {
            return;
        }

        List<Modification> serverModifications = new ArrayList<>( mods.size() );

        for ( Modification mod : mods )
        {
            serverModifications.add( new DefaultModification( directoryService.getSchemaManager(), mod ) );
        }

        ModifyOperationContext modifyContext = new ModifyOperationContext( this, dn, serverModifications );

        setReferralHandling( modifyContext, ignoreReferral );
        modifyContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.modify( modifyContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( Dn dn, Dn newParent ) throws LdapException
    {
        move( dn, newParent, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( Dn dn, Dn newParent, LogChange log ) throws LdapException
    {
        MoveOperationContext moveContext = new MoveOperationContext( this, dn, newParent );
        moveContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.move( moveContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( Dn dn, Dn newParent, boolean ignoreReferral ) throws Exception
    {
        move( dn, newParent, ignoreReferral, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( Dn dn, Dn newParent, boolean ignoreReferral, LogChange log ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();
        MoveOperationContext moveContext = new MoveOperationContext( this, dn, newParent );

        setReferralHandling( moveContext, ignoreReferral );
        moveContext.setLogChange( log );

        operationManager.move( moveContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn dn, Dn newParent, Rdn newRdn, boolean deleteOldRdn ) throws LdapException
    {
        moveAndRename( dn, newParent, newRdn, deleteOldRdn, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn dn, Dn newSuperiorDn, Rdn newRdn, boolean deleteOldRdn, LogChange log )
        throws LdapException
    {
        MoveAndRenameOperationContext moveAndRenameContext = new MoveAndRenameOperationContext( this, dn,
            newSuperiorDn, newRdn, deleteOldRdn );

        moveAndRenameContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.moveAndRename( moveAndRenameContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn dn, Dn newParent, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral )
        throws LdapException
    {
        moveAndRename( dn, newParent, newRdn, deleteOldRdn, ignoreReferral, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn dn, Dn newParent, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral,
        LogChange log ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();
        MoveAndRenameOperationContext moveAndRenameContext = new MoveAndRenameOperationContext( this, dn, newParent,
            newRdn, deleteOldRdn );

        moveAndRenameContext.setLogChange( log );
        setReferralHandling( moveAndRenameContext, ignoreReferral );

        operationManager.moveAndRename( moveAndRenameContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn dn, Rdn newRdn, boolean deleteOldRdn ) throws LdapException
    {
        rename( dn, newRdn, deleteOldRdn, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn dn, Rdn newRdn, boolean deleteOldRdn, LogChange log ) throws LdapException
    {
        RenameOperationContext renameContext = new RenameOperationContext( this, dn, newRdn, deleteOldRdn );

        renameContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();

        operationManager.rename( renameContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn dn, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral ) throws LdapException
    {
        rename( dn, newRdn, deleteOldRdn, ignoreReferral, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn dn, Rdn newRdn, boolean deleteOldRdn, boolean ignoreReferral, LogChange log )
        throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();
        RenameOperationContext renameContext = new RenameOperationContext( this, dn, newRdn, deleteOldRdn );

        renameContext.setLogChange( log );
        setReferralHandling( renameContext, ignoreReferral );

        operationManager.rename( renameContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cursor<Entry> search( Dn dn, String filter ) throws LdapException
    {
        return search( dn, filter, true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cursor<Entry> search( Dn dn, String filter, boolean ignoreReferrals ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();
        ExprNode filterNode = null;

        try
        {
            filterNode = FilterParser.parse( directoryService.getSchemaManager(), filter );
        }
        catch ( ParseException pe )
        {
            throw new LdapInvalidSearchFilterException( pe.getMessage() );
        }

        SearchOperationContext searchContext = new SearchOperationContext( this, dn, SearchScope.OBJECT, filterNode,
            ( String ) null );
        searchContext.setAliasDerefMode( AliasDerefMode.DEREF_ALWAYS );
        setReferralHandling( searchContext, ignoreReferrals );

        return operationManager.search( searchContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cursor<Entry> search( Dn dn, SearchScope scope, ExprNode filter, AliasDerefMode aliasDerefMode,
        String... returningAttributes ) throws LdapException
    {
        OperationManager operationManager = directoryService.getOperationManager();

        SearchOperationContext searchContext = new SearchOperationContext( this, dn, scope, filter, returningAttributes );
        searchContext.setAliasDerefMode( aliasDerefMode );

        return operationManager.search( searchContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAnonymous()
    {
        if ( ( authorizedPrincipal == null ) && ( authenticatedPrincipal == null ) )
        {
            return true;
        }
        else
        {
            return authenticatedPrincipal.getAuthenticationLevel() == AuthenticationLevel.NONE;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( CompareRequest compareRequest ) throws LdapException
    {
        CompareOperationContext compareContext = new CompareOperationContext( this, compareRequest );
        OperationManager operationManager = directoryService.getOperationManager();
        boolean result = false;
        try
        {
            result = operationManager.compare( compareContext );
        }
        catch ( LdapException e )
        {
            compareRequest.getResultResponse().addAllControls( compareContext.getResponseControls() );
            throw e;
        }

        compareRequest.getResultResponse().addAllControls( compareContext.getResponseControls() );
        return result;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( DeleteRequest deleteRequest ) throws LdapException
    {
        delete( deleteRequest, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( DeleteRequest deleteRequest, LogChange log ) throws LdapException
    {
        DeleteOperationContext deleteContext = new DeleteOperationContext( this, deleteRequest );

        deleteContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();

        try
        {
            operationManager.delete( deleteContext );
        }
        catch ( LdapException e )
        {
            deleteRequest.getResultResponse().addAllControls( deleteContext.getResponseControls() );
            throw e;
        }

        deleteRequest.getResultResponse().addAllControls( deleteContext.getResponseControls() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean exists( String dn ) throws LdapException
    {
        return exists( new Dn( dn ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean exists( Dn dn ) throws LdapException
    {
        HasEntryOperationContext hasEntryContext = new HasEntryOperationContext( this, dn );
        OperationManager operationManager = directoryService.getOperationManager();

        return operationManager.hasEntry( hasEntryContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( ModifyRequest modifyRequest ) throws LdapException
    {
        modify( modifyRequest, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( ModifyRequest modifyRequest, LogChange log ) throws LdapException
    {
        ModifyOperationContext modifyContext = new ModifyOperationContext( this, modifyRequest );

        modifyContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();

        try
        {
            operationManager.modify( modifyContext );
        }
        catch ( LdapException e )
        {
            modifyRequest.getResultResponse().addAllControls( modifyContext.getResponseControls() );
            throw e;
        }

        modifyRequest.getResultResponse().addAllControls( modifyContext.getResponseControls() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( ModifyDnRequest modifyDnRequest ) throws LdapException
    {
        move( modifyDnRequest, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( ModifyDnRequest modifyDnRequest, LogChange log ) throws LdapException
    {
        MoveOperationContext moveContext = new MoveOperationContext( this, modifyDnRequest );

        moveContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();

        try
        {
            operationManager.move( moveContext );
        }
        catch ( LdapException e )
        {
            modifyDnRequest.getResultResponse().addAllControls( moveContext.getResponseControls() );
            throw e;
        }

        modifyDnRequest.getResultResponse().addAllControls( moveContext.getResponseControls() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( ModifyDnRequest modifyDnRequest ) throws LdapException
    {
        moveAndRename( modifyDnRequest, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( ModifyDnRequest modifyDnRequest, LogChange log ) throws LdapException
    {
        MoveAndRenameOperationContext moveAndRenameContext = new MoveAndRenameOperationContext( this, modifyDnRequest );

        moveAndRenameContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();

        try
        {
            operationManager.moveAndRename( moveAndRenameContext );
        }
        catch ( LdapException e )
        {
            modifyDnRequest.getResultResponse().addAllControls( moveAndRenameContext.getResponseControls() );
            throw e;
        }

        modifyDnRequest.getResultResponse().addAllControls( moveAndRenameContext.getResponseControls() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( ModifyDnRequest modifyDnRequest ) throws LdapException
    {
        rename( modifyDnRequest, LogChange.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( ModifyDnRequest modifyDnRequest, LogChange log ) throws LdapException
    {
        RenameOperationContext renameContext = new RenameOperationContext( this, modifyDnRequest );

        renameContext.setLogChange( log );

        OperationManager operationManager = directoryService.getOperationManager();

        try
        {
            operationManager.rename( renameContext );
        }
        catch ( LdapException e )
        {
            modifyDnRequest.getResultResponse().addAllControls( renameContext.getResponseControls() );
            throw e;
        }

        modifyDnRequest.getResultResponse().addAllControls( renameContext.getResponseControls() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cursor<Entry> search( SearchRequest searchRequest ) throws LdapException
    {
        SearchOperationContext searchContext = new SearchOperationContext( this, searchRequest );
        searchContext.setSyncreplSearch( searchRequest.getControls().containsKey( SyncRequestValue.OID ) );

        OperationManager operationManager = directoryService.getOperationManager();

        // Check if we received serverside sort Control
        SortRequest sortControl = ( SortRequest ) searchRequest.getControls().get( SortRequest.OID );

        SortResponse sortRespCtrl = null;

        ResultResponse done = searchRequest.getResultResponse();

        LdapResult ldapResult = done.getLdapResult();

        if ( sortControl != null )
        {
            sortRespCtrl = canSort( sortControl, ldapResult, getDirectoryService().getSchemaManager() );

            if ( sortControl.isCritical() && ( sortRespCtrl.getSortResult() != SortResultCode.SUCCESS ) )
            {
                ldapResult.setResultCode( ResultCodeEnum.UNAVAILABLE_CRITICAL_EXTENSION );
                done.addControl( sortRespCtrl );

                return new EmptyCursor<>();
            }
        }

        Cursor<Entry> cursor = null;

        try
        {
            cursor = operationManager.search( searchContext );

            if ( ( sortRespCtrl != null ) && ( sortRespCtrl.getSortResult() == SortResultCode.SUCCESS ) )
            {
                cursor = sortResults( cursor, sortControl, getDirectoryService().getSchemaManager() );
            }

            // the below condition is to satisfy the scenario 6 in section 2 of rfc2891
            if ( sortRespCtrl != null )
            {
                cursor.beforeFirst();

                if ( !cursor.next() )
                {
                    sortRespCtrl = null;
                }
                else
                {
                    // move the cursor back
                    cursor.previous();
                }
            }
        }
        catch ( LdapException e )
        {
            done.addAllControls( searchContext.getResponseControls() );
            throw e;
        }
        catch ( Exception e )
        {
            done.addAllControls( searchContext.getResponseControls() );
            throw new LdapException( e );
        }
        finally
        {
            // Don't close the transaction !!!
            LOG.debug( "Search done, the transaction is still opened" );
        }

        if ( sortRespCtrl != null )
        {
            done.addControl( sortRespCtrl );
        }

        done.addAllControls( searchContext.getResponseControls() );

        return cursor;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unbind() throws LdapException
    {
        UnbindOperationContext unbindContext = new UnbindOperationContext( this );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.unbind( unbindContext );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unbind( UnbindRequest unbindRequest ) throws LdapException
    {
        UnbindOperationContext unbindContext = new UnbindOperationContext( this, unbindRequest );

        OperationManager operationManager = directoryService.getOperationManager();
        operationManager.unbind( unbindContext );
    }


    /**
     * Checks if the requested search results can be sorted
     * 
     * @param sortControl the sort control
     * @param ldapResult the refrence to the LDAP result of the ongoing search operation
     * @param session the current session
     * @return a sort response control
     */
    private SortResponse canSort( SortRequest sortControl, LdapResult ldapResult, SchemaManager schemaManager )
    {
        SortResponse resp = new SortResponseImpl();

        List<SortKey> keys = sortControl.getSortKeys();

        // only ONE key is supported by the server for now
        if ( keys.size() > 1 )
        {
            ldapResult.setDiagnosticMessage( "Cannot sort results based on more than one attribute" );
            resp.setSortResult( SortResultCode.UNWILLINGTOPERFORM );
            return resp;
        }

        SortKey sk = keys.get( 0 );

        AttributeType at = schemaManager.getAttributeType( sk.getAttributeTypeDesc() );

        if ( at == null )
        {
            ldapResult.setDiagnosticMessage( "No attribute with the name " + sk.getAttributeTypeDesc()
                + " exists in the server's schema" );
            resp.setSortResult( SortResultCode.NOSUCHATTRIBUTE );
            resp.setAttributeName( sk.getAttributeTypeDesc() );
            return resp;
        }

        String mrOid = sk.getMatchingRuleId();

        if ( mrOid != null )
        {
            MatchingRule mr = at.getOrdering();

            if ( ( mr != null ) && ( !mrOid.equals( mr.getOid() ) ) )
            {
                ldapResult.setDiagnosticMessage( "Given matchingrule " + mrOid
                    + " is not applicable for the attribute " + sk.getAttributeTypeDesc() );
                resp.setSortResult( SortResultCode.INAPPROPRIATEMATCHING );
                resp.setAttributeName( sk.getAttributeTypeDesc() );
                return resp;
            }

            try
            {
                schemaManager.lookupComparatorRegistry( mrOid );
            }
            catch ( LdapException e )
            {
                ldapResult.setDiagnosticMessage( "Given matchingrule " + mrOid + " is not supported" );
                resp.setSortResult( SortResultCode.INAPPROPRIATEMATCHING );
                resp.setAttributeName( sk.getAttributeTypeDesc() );
                return resp;
            }
        }
        else
        {
            MatchingRule mr = at.getOrdering();

            if ( mr == null )
            {
                mr = at.getEquality();
            }

            ldapResult.setDiagnosticMessage( "Matchingrule is required for sorting by the attribute "
                + sk.getAttributeTypeDesc() );
            resp.setSortResult( SortResultCode.INAPPROPRIATEMATCHING );
            resp.setAttributeName( sk.getAttributeTypeDesc() );

            if ( mr == null )
            {
                return resp;
            }

            try
            {
                schemaManager.lookupComparatorRegistry( mr.getOid() );
            }
            catch ( LdapException e )
            {
                return resp;
            }
        }

        resp.setSortResult( SortResultCode.SUCCESS );

        return resp;
    }


    /**
     * Sorts the entries based on the given sortkey and returns the cursor
     * 
     * @param unsortedEntries the cursor containing un-sorted entries
     * @param control the sort control
     * @param schemaManager schema manager
     * @return a cursor containing sorted entries
     * @throws CursorException
     * @throws LdapException
     * @throws IOException
     * @throws KeyNotFoundException 
     */
    private Cursor<Entry> sortResults( Cursor<Entry> unsortedEntries, SortRequest control, SchemaManager schemaManager )
        throws CursorException, LdapException, IOException
    {
        unsortedEntries.beforeFirst();

        Entry first = null;

        if ( unsortedEntries.next() )
        {
            first = unsortedEntries.get();
        }

        if ( !unsortedEntries.next() )
        {
            unsortedEntries.beforeFirst();

            return unsortedEntries;
        }

        SortKey sk = control.getSortKeys().get( 0 );

        AttributeType at = schemaManager.getAttributeType( sk.getAttributeTypeDesc() );

        SortedEntryComparator comparator = new SortedEntryComparator( at, sk.getMatchingRuleId(), sk.isReverseOrder(),
            schemaManager );

        SortedEntrySerializer keySerializer = new SortedEntrySerializer();
        SortedEntrySerializer.setSchemaManager( schemaManager );
        
        File file = null;
        
        try 
        {
            file = Files.createTempFile( "replica", ".sorted-data" ).toFile();    // see DIRSERVER-2007
        } 
        catch ( IOException e ) 
        {
            // see DIRSERVER-2091
            LOG.error( "Error creating temp file in directory {} for sorting: {}",  
                System.getProperty( "java.io.tmpdir" ),  e.getMessage(), e );
            throw e;
        }

        BaseRecordManager recMan = new BaseRecordManager( file.getAbsolutePath() );

        jdbm.btree.BTree<Entry, String> btree = new jdbm.btree.BTree<>( recMan, comparator, keySerializer, NullStringSerializer.INSTANCE );
        

        btree.insert( first, "", false );

        // at this stage the cursor will be _on_ the next element, so read it
        btree.insert( unsortedEntries.get(), "", false );

        while ( unsortedEntries.next() )
        {
            Entry entry = unsortedEntries.get();
            btree.insert( entry, "", false );
        }

        unsortedEntries.close();

        return new SortedEntryCursor( btree, recMan, file );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isPwdMustChange() 
    {
        return pwdMustChange;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setPwdMustChange( boolean pwdMustChange ) 
    {
        this.pwdMustChange = pwdMustChange;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasSessionTransaction()
    {
        return hasSessionTransaction;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public long beginSessionTransaction()
    {
        hasSessionTransaction = true;
        
        return transactionId.getAndIncrement();
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void endSessionTransaction( boolean commit ) throws IOException
    {
        if ( commit )
        {
            for ( Map.Entry<String, PartitionTxn> partitionTxn : transactionMap.entrySet() )
            {
                partitionTxn.getValue().commit();
            }
        }
        else
        {
            for ( Map.Entry<String, PartitionTxn> partitionTxn : transactionMap.entrySet() )
            {
                partitionTxn.getValue().abort();
            }
        }
        
        hasSessionTransaction = false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PartitionTxn getTransaction( Partition partition ) 
    {
        return transactionMap.get( partition.getId() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addTransaction( Partition partition, PartitionTxn transaction )
    {
        if ( !transactionMap.containsKey( partition.getId() ) )
        {
            transactionMap.put( partition.getId(), transaction );
        }
    }

    @Override
	public HashMap<Object, Object> getUserSession() {
		return this.userSession;
	}
}
