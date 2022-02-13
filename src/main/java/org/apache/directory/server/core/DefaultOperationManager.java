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
package org.apache.directory.server.core;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.directory.api.ldap.extras.controls.ad.TreeDelete;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.exception.LdapOperationErrorException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.exception.LdapPartialResultException;
import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.exception.LdapServiceUnavailableException;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.server.constants.ApacheSchemaConstants;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.OperationManager;
import org.apache.directory.server.core.api.ReferralManager;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.api.interceptor.context.CompareOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.GetRootDseOperationContext;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The default implementation of an OperationManager.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultOperationManager implements OperationManager
{
    /** A logger specifically for operations */
    private static final Logger OPERATION_LOG = LoggerFactory.getLogger( Loggers.OPERATION_LOG.getName() );

    /** A logger specifically for operations time */
    private static final Logger OPERATION_TIME = LoggerFactory.getLogger( Loggers.OPERATION_TIME.getName() );

    /** A logger specifically for operations statistics */
    private static final Logger OPERATION_STAT = LoggerFactory.getLogger( Loggers.OPERATION_STAT.getName() );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = OPERATION_LOG.isDebugEnabled();
    private static final boolean IS_TIME = OPERATION_TIME.isDebugEnabled();
    private static final boolean IS_STAT = OPERATION_STAT.isDebugEnabled();

    /** The directory service instance */
    private final DirectoryService directoryService;

    /** A lock used to protect against concurrent operations */
    private ReadWriteLock rwLock = new ReentrantReadWriteLock( true );

    /** A reference to the ObjectClass AT */
    protected AttributeType objectClassAT;
    
    /** The nbChildren count attributeType */
    protected AttributeType nbChildrenAT;
    
    public DefaultOperationManager( DirectoryService directoryService )
    {
        this.directoryService = directoryService;
    }


    /**
     * {@inheritDoc}
     */
    public ReadWriteLock getRWLock()
    {
        return rwLock;
    }


    /**
     * Acquires a ReadLock
     */
    public void lockRead()
    {
        rwLock.readLock().lock();
    }


    /**
     * Acquires a WriteLock
     */
    public void lockWrite()
    {
        rwLock.writeLock().lock();
    }


    /**
     * Releases a WriteLock
     */
    public void unlockWrite()
    {
        rwLock.writeLock().unlock();
    }


    /**
     * Releases a ReadLock
     */
    public void unlockRead()
    {
        rwLock.readLock().unlock();
    }


    /**
     * Eagerly populates fields of operation contexts so multiple Interceptors
     * in the processing pathway can reuse this value without performing a
     * redundant lookup operation.
     *
     * @param opContext the operation context to populate with cached fields
     */
    private void eagerlyPopulateFields( OperationContext opContext ) throws LdapException
    {
        // If the entry field is not set for ops other than add for example
        // then we set the entry but don't freak if we fail to do so since it
        // may not exist in the first place

        if ( opContext.getEntry() == null )
        {
            // We have to use the admin session here, otherwise we may have
            // trouble reading the entry due to insufficient access rights
            CoreSession adminSession = opContext.getSession().getDirectoryService().getAdminSession();

            LookupOperationContext lookupContext = new LookupOperationContext( adminSession, opContext.getDn(),
                SchemaConstants.ALL_ATTRIBUTES_ARRAY );
            lookupContext.setPartition( opContext.getPartition() );
            lookupContext.setTransaction( opContext.getTransaction() );
            Entry foundEntry = opContext.getSession().getDirectoryService().getPartitionNexus().lookup( lookupContext );

            if ( foundEntry != null )
            {
                opContext.setEntry( foundEntry );
            }
            else
            {
                // This is an error : we *must* have an entry if we want to be able to rename.
                throw new LdapNoSuchObjectException( I18n.err( I18n.ERR_256_NO_SUCH_OBJECT, opContext.getDn() ) );
            }
        }
    }


    private Entry getOriginalEntry( OperationContext opContext ) throws LdapException
    {
        // We have to use the admin session here, otherwise we may have
        // trouble reading the entry due to insufficient access rights
        CoreSession adminSession = opContext.getSession().getDirectoryService().getAdminSession();

        Entry foundEntry = adminSession.lookup( opContext.getDn(), SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES,
            SchemaConstants.ALL_USER_ATTRIBUTES );

        if ( foundEntry != null )
        {
            return foundEntry;
        }
        else
        {
            // This is an error : we *must* have an entry if we want to be able to rename.
            throw new LdapNoSuchObjectException( I18n.err( I18n.ERR_256_NO_SUCH_OBJECT,
                opContext.getDn() ) );
        }
    }


    private LdapReferralException buildReferralException( Entry parentEntry, Dn childDn ) throws LdapException
    {
        // Get the Ref attributeType
        Attribute refs = parentEntry.get( SchemaConstants.REF_AT );

        List<String> urls = new ArrayList<>();

        try
        {
            // manage each Referral, building the correct URL for each of them
            for ( Value url : refs )
            {
                // we have to replace the parent by the referral
                LdapUrl ldapUrl = new LdapUrl( url.getString() );

                // We have a problem with the Dn : we can't use the UpName,
                // as we may have some spaces around the ',' and '+'.
                // So we have to take the Rdn one by one, and create a
                // new Dn with the type and value UP form

                Dn urlDn = ldapUrl.getDn().add( childDn );

                ldapUrl.setDn( urlDn );
                urls.add( ldapUrl.toString() );
            }
        }
        catch ( LdapURLEncodingException luee )
        {
            throw new LdapOperationErrorException( luee.getMessage(), luee );
        }

        // Return with an exception
        LdapReferralException lre = new LdapReferralException( urls );
        lre.setRemainingDn( childDn );
        lre.setResolvedDn( parentEntry.getDn() );
        lre.setResolvedObject( parentEntry );

        return lre;
    }


    private LdapReferralException buildReferralExceptionForSearch( Entry parentEntry, Dn childDn, SearchScope scope )
        throws LdapException
    {
        // Get the Ref attributeType
        Attribute refs = parentEntry.get( SchemaConstants.REF_AT );

        List<String> urls = new ArrayList<>();

        // manage each Referral, building the correct URL for each of them
        for ( Value url : refs )
        {
            // we have to replace the parent by the referral
            try
            {
                LdapUrl ldapUrl = new LdapUrl( url.getString() );

                StringBuilder urlString = new StringBuilder();

                if ( ( ldapUrl.getDn() == null ) || ( ldapUrl.getDn() == Dn.ROOT_DSE ) )
                {
                    ldapUrl.setDn( parentEntry.getDn() );
                }
                else
                {
                    // We have a problem with the Dn : we can't use the UpName,
                    // as we may have some spaces around the ',' and '+'.
                    // So we have to take the Rdn one by one, and create a
                    // new Dn with the type and value UP form

                    Dn urlDn = ldapUrl.getDn().add( childDn );

                    ldapUrl.setDn( urlDn );
                }

                urlString.append( ldapUrl.toString() ).append( "??" );

                switch ( scope )
                {
                    case OBJECT:
                        urlString.append( "base" );
                        break;

                    case SUBTREE:
                        urlString.append( "sub" );
                        break;

                    case ONELEVEL:
                        urlString.append( "one" );
                        break;

                    default:
                        throw new IllegalArgumentException( "Unexpected scope " + scope );
                }

                urls.add( urlString.toString() );
            }
            catch ( LdapURLEncodingException luee )
            {
                // The URL is not correct, returns it as is
                urls.add( url.getString() );
            }
        }

        // Return with an exception
        LdapReferralException lre = new LdapReferralException( urls );
        lre.setRemainingDn( childDn );
        lre.setResolvedDn( parentEntry.getDn() );
        lre.setResolvedObject( parentEntry );

        return lre;
    }


    private LdapPartialResultException buildLdapPartialResultException( Dn childDn )
    {
        LdapPartialResultException lpre = new LdapPartialResultException( I18n.err( I18n.ERR_315 ) );

        lpre.setRemainingDn( childDn );
        lpre.setResolvedDn( Dn.EMPTY_DN );

        return lpre;
    }


    /**
     * {@inheritDoc}
     */
    public void add( AddOperationContext addContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> AddOperation : {}", addContext );
        }

        long addStart = 0L;

        if ( IS_TIME )
        {
            addStart = System.nanoTime();
        }

        ensureStarted();

        // Normalize the addContext Dn
        Dn dn = addContext.getDn();
        
        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            addContext.setDn( dn );
        }
        
        
        
        

        // Call the Add method
        Interceptor head = directoryService.getInterceptor( addContext.getNextInterceptor() );

        
        head.add( addContext );
            
        

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< AddOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Add operation took {} ns", ( System.nanoTime() - addStart ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void bind( BindOperationContext bindContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> BindOperation : {}", bindContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Call the Delete method
        Interceptor head = directoryService.getInterceptor( bindContext.getNextInterceptor() );

        // Normalize the addContext Dn
        Dn dn = bindContext.getDn();
        
        if ( ( dn != null ) && !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            bindContext.setDn( dn );
        }

        
        head.bind( bindContext );
        

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< BindOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Bind operation took {} ns", ( System.nanoTime() - opStart )  );
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean compare( CompareOperationContext compareContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> CompareOperation : {}", compareContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();
        
        // Normalize the compareContext Dn
        Dn dn = compareContext.getDn();

        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            compareContext.setDn( dn );
        }

        // We have to deal with the referral first
        directoryService.getReferralManager().lockRead();

        try
        {
            // Check if we have an ancestor for this Dn
            Entry parentEntry = directoryService.getReferralManager().getParentReferral( dn );

            if ( parentEntry != null )
            {
                // We have found a parent referral for the current Dn
                Dn childDn = dn.getDescendantOf( parentEntry.getDn() );

                if ( directoryService.getReferralManager().isReferral( dn ) )
                {
                    // This is a referral. We can delete it if the ManageDsaIt flag is true
                    // Otherwise, we just throw a LdapReferralException
                    if ( !compareContext.isReferralIgnored() )
                    {
                        // Throw a Referral Exception
                        throw buildReferralException( parentEntry, childDn );
                    }
                }
                else if ( directoryService.getReferralManager().hasParentReferral( dn ) )
                {
                    // Depending on the Context.REFERRAL property value, we will throw
                    // a different exception.
                    if ( compareContext.isReferralIgnored() )
                    {
                        throw buildLdapPartialResultException( childDn );
                    }
                    else
                    {
                        throw buildReferralException( parentEntry, childDn );
                    }
                }
            }
        }
        finally
        {
            // Unlock the ReferralManager
            directoryService.getReferralManager().unlock();
        }

        // populate the context with the old entry
        //compareContext.setOriginalEntry( getOriginalEntry( compareContext ) );

        // Call the Compare method
        Interceptor head = directoryService.getInterceptor( compareContext.getNextInterceptor() );

        boolean result = false;

        lockRead();

        try
        {
            Partition partition = directoryService.getPartitionNexus().getPartition( dn );
            
            try ( PartitionTxn partitionTxn = partition.beginReadTransaction() )
            {
                compareContext.setPartition( partition );
                compareContext.setTransaction( partitionTxn );
                
                result = head.compare( compareContext );
            }
            catch ( IOException ioe )
            {
                throw new LdapOtherException( ioe.getMessage(), ioe );
            }
        }
        finally
        {
            unlockRead();
        }

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< CompareOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Compare operation took {} ns", ( System.nanoTime() - opStart ) );
        }

        return result;
    }
    
    
    private void deleteEntry( DeleteOperationContext deleteContext, Dn dn ) throws LdapException
    {
        DeleteOperationContext entryDeleteContext = 
            new DeleteOperationContext( deleteContext.getSession(), dn );
        entryDeleteContext.setTransaction( deleteContext.getTransaction() );

        eagerlyPopulateFields( entryDeleteContext );
        
        // Call the Delete method
        Interceptor head = directoryService.getInterceptor( deleteContext.getNextInterceptor() );

        head.delete( entryDeleteContext );
    }
    
    
    private void processTreeDelete( DeleteOperationContext deleteContext, Dn dn ) throws LdapException, CursorException
    {
        objectClassAT = directoryService.getSchemaManager().getAttributeType( SchemaConstants.OBJECT_CLASS_AT );
        nbChildrenAT = directoryService.getSchemaManager().getAttributeType( ApacheSchemaConstants.NB_CHILDREN_OID );

        // This is a depth first recursive operation
        PresenceNode filter = new PresenceNode( objectClassAT );
        SearchOperationContext searchContext = new SearchOperationContext( 
            deleteContext.getSession(), 
            dn, 
            SearchScope.ONELEVEL, filter,
            ApacheSchemaConstants.NB_CHILDREN_OID );
        searchContext.setTransaction( deleteContext.getTransaction() );

        EntryFilteringCursor cursor = search( searchContext );
        
        cursor.beforeFirst();
        
        while ( cursor.next() )
        {
            Entry entry = cursor.get();
            
            if ( Integer.parseInt( entry.get( nbChildrenAT ).getString() ) == 0 )
            {
                // We can delete the entry
                deleteEntry( deleteContext, entry.getDn() );
            }
            else
            {
                // Recurse
                processTreeDelete( deleteContext, entry.getDn() );
            }
        }
        
        // Done with the children, we can delete the entry
        // We can delete the entry
        deleteEntry( deleteContext, dn );
    }


    /**
     * {@inheritDoc}
     */
    public void delete( DeleteOperationContext deleteContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> DeleteOperation : {}", deleteContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Normalize the deleteContext Dn
        Dn dn = deleteContext.getDn();
        
        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            deleteContext.setDn( dn );
        }

 

        
    
        // Call the Delete method
        Interceptor head = directoryService.getInterceptor( deleteContext.getNextInterceptor() );

        head.delete( deleteContext );

                

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< DeleteOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Delete operation took {} ns", ( System.nanoTime() - opStart ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public Entry getRootDse( GetRootDseOperationContext getRootDseContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> GetRootDseOperation : {}", getRootDseContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        Interceptor head = directoryService.getInterceptor( getRootDseContext.getNextInterceptor() );
        Entry root;

        try
        {
            lockRead();
            
            Partition partition = directoryService.getPartitionNexus().getPartition( Dn.ROOT_DSE );
            
            try ( PartitionTxn partitionTxn = partition.beginReadTransaction() )
            {
                getRootDseContext.setPartition( partition );
                getRootDseContext.setTransaction( partitionTxn );
                
                root = head.getRootDse( getRootDseContext );
            }
            catch ( IOException ioe )
            {
                throw new LdapOtherException( ioe.getMessage(), ioe );
            }
        }
        finally
        {
            unlockRead();
        }

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< getRootDseOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "GetRootDSE operation took {} ns", ( System.nanoTime() - opStart ) );
        }

        return root;
    }


    /**
     * {@inheritDoc}
     */
    public boolean hasEntry( HasEntryOperationContext hasEntryContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> hasEntryOperation : {}", hasEntryContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        Interceptor head = directoryService.getInterceptor( hasEntryContext.getNextInterceptor() );

        boolean result = false;

        lockRead();

        // Normalize the addContext Dn
        Dn dn = hasEntryContext.getDn();
        
        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            hasEntryContext.setDn( dn );
        }

        try
        {
            Partition partition = directoryService.getPartitionNexus().getPartition( dn );

            try ( PartitionTxn partitionTxn = partition.beginReadTransaction() )
            {
                hasEntryContext.setPartition( partition );
                hasEntryContext.setTransaction( partitionTxn );

                result = head.hasEntry( hasEntryContext );
            }
            catch ( IOException ioe )
            {
                throw new LdapOtherException( ioe.getMessage(), ioe );
            }
        }
        finally
        {
            unlockRead();
        }

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< HasEntryOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "HasEntry operation took {} ns", ( System.nanoTime() - opStart ) );
        }

        return result;
    }


    /**
     * {@inheritDoc}
     */
    public Entry lookup( LookupOperationContext lookupContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> LookupOperation : {}", lookupContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        Interceptor head = directoryService.getInterceptor( lookupContext.getNextInterceptor() );

        Entry entry = null;

        // Normalize the modifyContext Dn
        Dn dn = lookupContext.getDn();

        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            lookupContext.setDn( dn );
        }
        
        Partition partition = directoryService.getPartitionNexus().getPartition( dn );
        lookupContext.setPartition( partition );
        
        // Start a read transaction right away
        try ( PartitionTxn transaction = partition.beginReadTransaction() )
        {
            lookupContext.setTransaction( transaction );

            lockRead();
    
            try
            {
                entry = head.lookup( lookupContext );
            }
            finally
            {
                unlockRead();
            }
        }
        catch ( IOException ioe )
        {
            throw new LdapOtherException( ioe.getMessage(), ioe );
        }

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< LookupOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Lookup operation took {} ns", ( System.nanoTime() - opStart ) );
        }

        return entry;
    }


    /**
     * {@inheritDoc}
     */
    public void modify( ModifyOperationContext modifyContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> ModifyOperation : {}", modifyContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Normalize the modifyContext Dn
        Dn dn = modifyContext.getDn();

        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            modifyContext.setDn( dn );
        }

        

  

        // Call the Modify method
        Interceptor head = directoryService.getInterceptor( modifyContext.getNextInterceptor() );

        head.modify( modifyContext );
            
            

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< ModifyOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Modify operation took {} ns", ( System.nanoTime() - opStart ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void move( MoveOperationContext moveContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> MoveOperation : {}", moveContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Normalize the moveContext Dn
        Dn dn = moveContext.getDn();

        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            moveContext.setDn( dn );
        }

        // Normalize the moveContext superior Dn
        Dn newSuperiorDn = moveContext.getNewSuperior();

        if ( !newSuperiorDn.isSchemaAware() )
        {
            newSuperiorDn = new Dn( directoryService.getSchemaManager(), newSuperiorDn );
            moveContext.setNewSuperior( newSuperiorDn );
        }

        

        // Call the Move method
        Interceptor head = directoryService.getInterceptor( moveContext.getNextInterceptor() );

        head.move( moveContext );
            
        

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< MoveOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Move operation took {} ns", ( System.nanoTime() - opStart ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void moveAndRename( MoveAndRenameOperationContext moveAndRenameContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> MoveAndRenameOperation : {}", moveAndRenameContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Normalize the moveAndRenameContext Dn
        Dn dn = moveAndRenameContext.getDn();

        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            moveAndRenameContext.setDn( dn );
        }

        

        // Call the MoveAndRename method
        Interceptor head = directoryService.getInterceptor( moveAndRenameContext.getNextInterceptor() );

        head.moveAndRename( moveAndRenameContext );

            

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< MoveAndRenameOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "MoveAndRename operation took {} ns", ( System.nanoTime() - opStart ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void rename( RenameOperationContext renameContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> RenameOperation : {}", renameContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

       


        Interceptor head = directoryService.getInterceptor( renameContext.getNextInterceptor() );
        head.rename( renameContext );
            
         

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< RenameOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Rename operation took {} ns", ( System.nanoTime() - opStart ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public EntryFilteringCursor search( SearchOperationContext searchContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> SearchOperation : {}", searchContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Normalize the searchContext Dn
        Dn dn = searchContext.getDn();

        if ( !dn.isSchemaAware() )
        {
            dn = new Dn( directoryService.getSchemaManager(), dn );
            searchContext.setDn( dn );
        }

       

        // Call the Search method
        Interceptor head = directoryService.getInterceptor( searchContext.getNextInterceptor() );

        EntryFilteringCursor cursor = null;
        
        // don't care about partitions
        cursor = head.search( searchContext );
        
        
        /*Partition partition = directoryService.getPartitionNexus().getPartition( dn );
        
        try ( PartitionTxn partitionTxn = partition.beginReadTransaction() )
        {
            searchContext.setPartition( partition );
            searchContext.setTransaction( partitionTxn );
            lockRead();
    
            try
            {
                cursor = head.search( searchContext );
            }
            finally
            {
                unlockRead();
            }
        }
        catch ( IOException ioe )
        {
            throw new LdapOtherException( ioe.getMessage(), ioe );
        }*/

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< SearchOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Search operation took {} ns", ( System.nanoTime() - opStart ) );
        }

        return cursor;
    }


    /**
     * {@inheritDoc}
     */
    public void unbind( UnbindOperationContext unbindContext ) throws LdapException
    {
        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( ">> UnbindOperation : {}", unbindContext );
        }

        long opStart = 0L;

        if ( IS_TIME )
        {
            opStart = System.nanoTime();
        }

        ensureStarted();

        // Call the Unbind method
        Interceptor head = directoryService.getInterceptor( unbindContext.getNextInterceptor() );

        head.unbind( unbindContext );

        if ( IS_DEBUG )
        {
            OPERATION_LOG.debug( "<< UnbindOperation successful" );
        }

        if ( IS_TIME )
        {
            OPERATION_TIME.debug( "Unbind operation took {} ns", ( System.nanoTime() - opStart ) );
        }
    }


    private void ensureStarted() throws LdapServiceUnavailableException
    {
        if ( !directoryService.isStarted() )
        {
            throw new LdapServiceUnavailableException( ResultCodeEnum.UNAVAILABLE, I18n.err( I18n.ERR_316 ) );
        }
    }
}
