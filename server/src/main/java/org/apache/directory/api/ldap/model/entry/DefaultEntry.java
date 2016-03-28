/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.entry;


import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.sourceforge.myvd.server.apacheds.ApacheDSUtil;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.ldif.LdapLdifException;
import org.apache.directory.api.ldap.model.ldif.LdifAttributesReader;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Base64;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A default implementation of a ServerEntry which should suite most
 * use cases.<br/>
 * <br/>
 * This class is final, it should not be extended.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class DefaultEntry implements Entry
{
    /** Used for serialization */
    private static final long serialVersionUID = 2L;

    /** The logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultEntry.class );

    /** The Dn for this entry */
    private Dn dn;

    /** A map containing all the attributes for this entry */
    private Map<String, Attribute> attributes = new HashMap<String, Attribute>();

    /** A speedup to get the ObjectClass attribute */
    private static AttributeType objectClassAttributeType;

    /** The SchemaManager */
    private SchemaManager schemaManager;

    /** The computed hashcode. We don't want to compute it each time the hashcode() method is called */
    private volatile int h;

    /** A mutex to manage synchronization*/
    private static final Object MUTEX = new Object();


    //-------------------------------------------------------------------------
    // Constructors
    //-------------------------------------------------------------------------
    /**
     * Creates a new instance of DefaultEntry.
     * <p>
     * This entry <b>must</b> be initialized before being used !
     */
    public DefaultEntry()
    {
        this( ( SchemaManager ) null );
    }


    /**
     * <p>
     * Creates a new instance of DefaultEntry, schema aware.
     * </p>
     * <p>
     * No attributes will be created.
     * </p>
     *
     * @param schemaManager The reference to the schemaManager
     */
    public DefaultEntry( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
        dn = Dn.EMPTY_DN;

        // Initialize the ObjectClass object
        if ( schemaManager != null )
        {
            initObjectClassAT();
        }
    }


    /**
     * Creates a new instance of DefaultEntry, with a Dn.
     *
     * @param dn The String Dn for this serverEntry. Can be null.
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public DefaultEntry( String dn ) throws LdapInvalidDnException
    {
        this.dn = new Dn( dn );
    }


    /**
     * Creates a new instance of DefaultEntry, with a Dn.
     *
     * @param dn The Dn for this serverEntry. Can be null.
     */
    public DefaultEntry( Dn dn )
    {
        this.dn = dn;
    }


    /**
     * <p>
     * Creates a new instance of DefaultEntry, schema aware.
     * </p>
     * <p>
     * No attributes will be created.
     * </p>
     *
     * @param schemaManager The reference to the schemaManager
     * @param dn The String Dn for this serverEntry. Can be null.
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public DefaultEntry( SchemaManager schemaManager, String dn ) throws LdapInvalidDnException
    {
        this.schemaManager = schemaManager;

        if ( Strings.isEmpty( dn ) )
        {
            this.dn = Dn.EMPTY_DN;
        }
        else
        {
            this.dn = new Dn( dn );
            normalizeDN( this.dn );
        }

        // Initialize the ObjectClass object
        initObjectClassAT();
    }


    /**
     * <p>
     * Creates a new instance of DefaultEntry, schema aware.
     * </p>
     * <p>
     * No attributes will be created.
     * </p>
     *
     * @param schemaManager The reference to the schemaManager
     * @param dn The Dn for this serverEntry. Can be null.
     */
    public DefaultEntry( SchemaManager schemaManager, Dn dn )
    {
        this.schemaManager = schemaManager;

        if ( dn == null )
        {
            this.dn = Dn.EMPTY_DN;
        }
        else
        {
            this.dn = dn;
            normalizeDN( this.dn );
        }

        // Initialize the ObjectClass object
        initObjectClassAT();
    }


    /**
     * Creates a new instance of DefaultEntry, with a
     * Dn and a list of IDs.
     *
     * @param dn The Dn for this serverEntry. Can be null.
     * @param upIds The list of attributes to create.
     */
    public DefaultEntry( String dn, Object... elements ) throws LdapException
    {
        this( null, dn, elements );
    }


    /**
     * Creates a new instance of DefaultEntry, with a
     * Dn and a list of IDs.
     *
     * @param dn The Dn for this serverEntry. Can be null.
     * @param upIds The list of attributes to create.
     */
    public DefaultEntry( Dn dn, Object... elements ) throws LdapException
    {
        this( null, dn, elements );
    }


    /**
     * Creates a new instance of DefaultEntry, with a
     * Dn and a list of IDs.
     *
     * @param dn The Dn for this serverEntry. Can be null.
     * @param upIds The list of attributes to create.
     */
    public DefaultEntry( SchemaManager schemaManager, String dn, Object... elements ) throws LdapException
    {
        this( schemaManager, new Dn( schemaManager, dn ), elements );
    }


    /**
     * Creates a new instance of DefaultEntry, with a
     * Dn and a list of IDs.
     *
     * @param dn The Dn for this serverEntry. Can be null.
     * @param upIds The list of attributes to create.
     */
    public DefaultEntry( SchemaManager schemaManager, Dn dn, Object... elements ) throws LdapException
    {
        DefaultEntry entry = ( DefaultEntry ) createEntry( schemaManager, elements );

        this.dn = dn;
        this.attributes = entry.attributes;
        this.schemaManager = schemaManager;

        if ( schemaManager != null )
        {
            this.dn.apply( schemaManager );
            initObjectClassAT();
        }
    }


    /**
     * <p>
     * Creates a new instance of DefaultEntry, copying
     * another entry.
     * </p>
     * <p>
     * No attributes will be created.
     * </p>
     *
     * @param schemaManager The reference to the schemaManager
     * @param entry the entry to copy
     */
    /**
     * @param schemaManager
     * @param entry
     * @throws LdapException
     */
    public DefaultEntry( SchemaManager schemaManager, Entry entry ) throws LdapException
    {
        this.schemaManager = schemaManager;

        // Initialize the ObjectClass object
        initObjectClassAT();

        // We will clone the existing entry, because it may be normalized
        if ( entry.getDn() != null )
        {
            dn = entry.getDn();
            normalizeDN( dn );
        }
        else
        {
            dn = Dn.EMPTY_DN;
        }

        // Init the attributes map
        attributes = new HashMap<String, Attribute>( entry.size() );

        // and copy all the attributes
        for ( Attribute attribute : entry )
        {
            try
            {
                // First get the AttributeType
                AttributeType attributeType = attribute.getAttributeType();

                if ( attributeType == null )
                {
                    try {
                    	attributeType = schemaManager.lookupAttributeTypeRegistry( attribute.getId() );
                    } catch (LdapNoSuchAttributeException e) {
                    	attributeType = ApacheDSUtil.addAttributeToSchema(attribute, schemaManager);
                    }
                }

                // Create a new ServerAttribute.
                Attribute serverAttribute = new DefaultAttribute( attributeType, attribute );

                // And store it
                add( serverAttribute );
            }
            catch ( LdapException ne )
            {
                // Just log a warning
                LOG.warn( "The attribute '" + attribute.getId() + "' cannot be stored" );
                throw ne;
            }
        }
    }


    //-------------------------------------------------------------------------
    // Helper methods
    //-------------------------------------------------------------------------
    

    
    
    private Entry createEntry( SchemaManager schemaManager, Object... elements )
        throws LdapInvalidAttributeValueException, LdapLdifException
    {
        StringBuilder sb = new StringBuilder();
        int pos = 0;
        boolean valueExpected = false;

        for ( Object element : elements )
        {
            if ( !valueExpected )
            {
                if ( !( element instanceof String ) )
                {
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, I18n.err(
                        I18n.ERR_12085, ( pos + 1 ) ) );
                }

                String attribute = ( String ) element;
                sb.append( attribute );

                if ( attribute.indexOf( ':' ) != -1 )
                {
                    sb.append( '\n' );
                }
                else
                {
                    valueExpected = true;
                }
            }
            else
            {
                if ( element instanceof String )
                {
                    sb.append( ": " ).append( ( String ) element ).append( '\n' );
                }
                else if ( element instanceof byte[] )
                {
                    sb.append( ":: " );
                    sb.append( new String( Base64.encode( ( byte[] ) element ) ) );
                    sb.append( '\n' );
                }
                else
                {
                    throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, I18n.err(
                        I18n.ERR_12086, ( pos + 1 ) ) );
                }

                valueExpected = false;
            }
        }

        if ( valueExpected )
        {
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, I18n
                .err( I18n.ERR_12087 ) );
        }

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( schemaManager, sb.toString() );

        return entry;
    }


    /**
     * Get the trimmed and lower cased entry ID
     */
    private String getId( String upId )
    {
        String id = Strings.trim( Strings.toLowerCase( upId ) );

        // If empty, throw an error
        if ( Strings.isEmpty( id ) )
        {
            String message = I18n.err( I18n.ERR_04133 );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        return id;
    }


    /**
     * Get the UpId if it is null.
     * 
     * @param upId The ID
     */
    private String getUpId( String upId, AttributeType attributeType )
    {
        String normUpId = Strings.trim( upId );

        if ( ( attributeType == null ) )
        {
            if ( Strings.isEmpty( normUpId ) )
            {
                String message = I18n.err( I18n.ERR_04458 );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }

            return upId;
        }
        else if ( Strings.isEmpty( normUpId ) )
        {
            String id = attributeType.getName();

            if ( Strings.isEmpty( id ) )
            {
                id = attributeType.getOid();
            }

            return id;
        }
        else
        {
            return upId;
        }
    }


    /**
     * This method is used to initialize the OBJECT_CLASS_AT attributeType.
     *
     * We want to do it only once, so it's a synchronized method. Note that
     * the alternative would be to call the lookup() every time, but this won't
     * be very efficient, as it will get the AT from a map, which is also
     * synchronized, so here, we have a very minimal cost.
     *
     * We can't do it once as a static part in the body of this class, because
     * the access to the registries is mandatory to get back the AttributeType.
     */
    private void initObjectClassAT()
    {
        if ( schemaManager == null )
        {
            return;
        }

        try
        {
            synchronized ( MUTEX )
            {
                if ( objectClassAttributeType == null )
                {
                    objectClassAttributeType = schemaManager
                        .lookupAttributeTypeRegistry( SchemaConstants.OBJECT_CLASS_AT );
                }
            }
        }
        catch ( LdapException ne )
        {
            // do nothing...
        }
    }


    /**
     * normalizes the given Dn if it was not already normalized
     *
     * @param dn the Dn to be normalized
     */
    private void normalizeDN( Dn dn )
    {
        if ( !dn.isSchemaAware() )
        {
            try
            {
                // The dn must be normalized
                dn.apply( schemaManager );
            }
            catch ( LdapException ne )
            {
                LOG.warn( "The Dn '{}' cannot be normalized", dn );
            }
        }
    }


    /**
     * A helper method to recompute the hash code
     */
    private void rehash()
    {
        h = 37;
        h = h * 17 + dn.hashCode();
    }


    /**
     * Add a new EntryAttribute, with its upId. If the upId is null,
     * default to the AttributeType name.
     *
     * Updates the AttributeMap.
     */
    protected void createAttribute( String upId, AttributeType attributeType, byte[]... values )
        throws LdapInvalidAttributeValueException
    {
        Attribute attribute = new DefaultAttribute( attributeType, values );
        attribute.setUpId( upId, attributeType );
        attributes.put( attributeType.getOid(), attribute );
    }


    /**
     * Add a new EntryAttribute, with its upId. If the upId is null,
     * default to the AttributeType name.
     *
     * Updates the AttributeMap.
     */
    protected void createAttribute( String upId, AttributeType attributeType, String... values )
        throws LdapInvalidAttributeValueException
    {
        Attribute attribute = new DefaultAttribute( attributeType, values );
        attribute.setUpId( upId, attributeType );
        attributes.put( attributeType.getOid(), attribute );
    }


    /**
     * Add a new EntryAttribute, with its upId. If the upId is null,
     * default to the AttributeType name.
     *
     * Updates the AttributeMap.
     */
    protected void createAttribute( String upId, AttributeType attributeType, Value<?>... values )
        throws LdapInvalidAttributeValueException
    {
        Attribute attribute = new DefaultAttribute( attributeType, values );
        attribute.setUpId( upId, attributeType );
        attributes.put( attributeType.getOid(), attribute );
    }


    /**
     * Returns the attributeType from an Attribute ID.
     */
    protected AttributeType getAttributeType( String upId ) throws LdapException
    {
        if ( Strings.isEmpty( Strings.trim( upId ) ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        return schemaManager.lookupAttributeTypeRegistry( upId );
    }


    //-------------------------------------------------------------------------
    // Entry methods
    //-------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public void add( AttributeType attributeType, byte[]... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        if ( ( values == null ) || ( values.length == 0 ) )
        {
            String message = I18n.err( I18n.ERR_04478_NO_VALUE_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        // ObjectClass with binary values are not allowed
        if ( attributeType.equals( objectClassAttributeType ) )
        {
            String message = I18n.err( I18n.ERR_04461 );
            LOG.error( message );
            throw new UnsupportedOperationException( message );
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            // This Attribute already exist, we add the values
            // into it
            attribute.add( values );
        }
        else
        {
            // We have to create a new Attribute and set the values.
            // The upId, which is set to null, will be setup by the
            // createAttribute method
            createAttribute( null, attributeType, values );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( AttributeType attributeType, String... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            // This Attribute already exist, we add the values
            // into it
            attribute.add( values );
        }
        else
        {
            // We have to create a new Attribute and set the values.
            // The upId, which is set to null, will be setup by the
            // createAttribute method
            createAttribute( null, attributeType, values );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            // This Attribute already exist, we add the values
            // into it
            attribute.add( values );
        }
        else
        {
            // We have to create a new Attribute and set the values.
            // The upId, which is set to null, will be setup by the
            // createAttribute method
            createAttribute( null, attributeType, values );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( String upId, AttributeType attributeType, byte[]... values ) throws LdapException
    {
        // ObjectClass with binary values are not allowed
        if ( attributeType.equals( objectClassAttributeType ) )
        {
            String message = I18n.err( I18n.ERR_04461 );
            LOG.error( message );
            throw new UnsupportedOperationException( message );
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        String id = getUpId( upId, attributeType );

        if ( attribute != null )
        {
            // This Attribute already exist, we add the values
            // into it
            attribute.add( values );
            attribute.setUpId( id, attributeType );
        }
        else
        {
            // We have to create a new Attribute and set the values
            // and the upId
            createAttribute( id, attributeType, values );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( String upId, AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        String id = getUpId( upId, attributeType );

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            // This Attribute already exist, we add the values
            // into it
            attribute.add( values );
            attribute.setUpId( id, attributeType );
        }
        else
        {
            createAttribute( id, attributeType, values );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( String upId, AttributeType attributeType, String... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        String id = getUpId( upId, attributeType );

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            // This Attribute already exist, we add the values
            // into it
            attribute.add( values );
            attribute.setUpId( id, attributeType );
        }
        else
        {
            // We have to create a new Attribute and set the values
            // and the upId
            createAttribute( id, attributeType, values );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( Attribute... attributes ) throws LdapException
    {
        // Loop on all the added attributes
        for ( Attribute attribute : attributes )
        {
            AttributeType attributeType = attribute.getAttributeType();

            if ( attributeType != null )
            {
                String oid = attributeType.getOid();

                if ( this.attributes.containsKey( oid ) )
                {
                    // We already have an attribute with the same AttributeType
                    // Just add the new values into it.
                    Attribute existingAttribute = this.attributes.get( oid );

                    for ( Value<?> value : attribute )
                    {
                        existingAttribute.add( value );
                    }

                    // And update the upId
                    existingAttribute.setUpId( attribute.getUpId() );
                }
                else
                {
                    // The attributeType does not exist, add it
                    this.attributes.put( oid, attribute );
                }
            }
            else
            {
                // If the attribute already exist, we will add the new values.
                if ( contains( attribute ) )
                {
                    Attribute existingAttribute = get( attribute.getId() );

                    // Loop on all the values, and add them to the existing attribute
                    for ( Value<?> value : attribute )
                    {
                        existingAttribute.add( value );
                    }
                }
                else
                {
                    // Stores the attribute into the entry
                    this.attributes.put( attribute.getId(), attribute );
                }
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( String upId, byte[]... values ) throws LdapException
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        // First, transform the upID to a valid ID
        String id = getId( upId );

        if ( schemaManager != null )
        {
            add( upId, schemaManager.lookupAttributeTypeRegistry( id ), values );
        }
        else
        {
            // Now, check to see if we already have such an attribute
            Attribute attribute = attributes.get( id );

            if ( attribute != null )
            {
                // This Attribute already exist, we add the values
                // into it. (If the values already exists, they will
                // not be added, but this is done in the add() method)
                attribute.add( values );
                attribute.setUpId( upId );
            }
            else
            {
                // We have to create a new Attribute and set the values
                // and the upId
                attributes.put( id, new DefaultAttribute( upId, values ) );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( String upId, String... values ) throws LdapException
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        // First, transform the upID to a valid ID
        String id = getId( upId );

        if ( schemaManager != null )
        {
            add( upId, schemaManager.lookupAttributeTypeRegistry( upId ), values );
        }
        else
        {
            // Now, check to see if we already have such an attribute
            Attribute attribute = attributes.get( id );

            if ( attribute != null )
            {
                // This Attribute already exist, we add the values
                // into it. (If the values already exists, they will
                // not be added, but this is done in the add() method)
                attribute.add( values );
                attribute.setUpId( upId );
            }
            else
            {
                // We have to create a new Attribute and set the values
                // and the upId
                attributes.put( id, new DefaultAttribute( upId, values ) );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public void add( String upId, Value<?>... values ) throws LdapException
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        // First, transform the upID to a valid ID
        String id = getId( upId );

        if ( schemaManager != null )
        {
            add( upId, schemaManager.lookupAttributeTypeRegistry( upId ), values );
        }
        else
        {
            // Now, check to see if we already have such an attribute
            Attribute attribute = attributes.get( id );

            if ( attribute != null )
            {
                // This Attribute already exist, we add the values
                // into it. (If the values already exists, they will
                // not be added, but this is done in the add() method)
                attribute.add( values );
                attribute.setUpId( upId );
            }
            else
            {
                // We have to create a new Attribute and set the values
                // and the upId
                attributes.put( id, new DefaultAttribute( upId, values ) );
            }
        }
    }


    /**
     * Clone an entry. All the element are duplicated, so a modification on
     * the original object won't affect the cloned object, as a modification
     * on the cloned object has no impact on the original object
     */
    @SuppressWarnings("unchecked")
    public Entry clone()
    {
        try
        {
            // First, clone the structure
            DefaultEntry clone = ( DefaultEntry ) super.clone();

            // Just in case ... Should *never* happen
            if ( clone == null )
            {
                return null;
            }

            // An Entry has a Dn and many attributes.
            clone.dn = dn; // note that Dn is immutable now

            // then clone the ClientAttribute Map.
            clone.attributes = ( Map<String, Attribute> ) ( ( ( HashMap<String, Attribute> ) attributes )
                .clone() );

            // now clone all the attributes
            clone.attributes.clear();

            if ( schemaManager != null )
            {
                for ( Attribute attribute : attributes.values() )
                {
                    String oid = attribute.getAttributeType().getOid();
                    clone.attributes.put( oid, attribute.clone() );
                }
            }
            else
            {
                for ( Attribute attribute : attributes.values() )
                {
                    clone.attributes.put( attribute.getId(), attribute.clone() );
                }

            }

            // We are done !
            return clone;
        }
        catch ( CloneNotSupportedException cnse )
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( Attribute... attributes )
    {
        if ( schemaManager == null )
        {
            for ( Attribute attribute : attributes )
            {
                if ( attribute == null )
                {
                    return this.attributes.size() == 0;
                }

                if ( !this.attributes.containsKey( attribute.getId() ) )
                {
                    return false;
                }
            }
        }
        else
        {
            for ( Attribute entryAttribute : attributes )
            {
                if ( entryAttribute == null )
                {
                    return this.attributes.size() == 0;
                }

                AttributeType attributeType = entryAttribute.getAttributeType();

                if ( ( attributeType == null ) || !this.attributes.containsKey( attributeType.getOid() ) )
                {
                    return false;
                }
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    public boolean containsAttribute( String... attributes )
    {
        if ( schemaManager == null )
        {
            for ( String attribute : attributes )
            {
                String id = getId( attribute );

                if ( !this.attributes.containsKey( id ) )
                {
                    return false;
                }
            }

            return true;
        }
        else
        {
            for ( String attribute : attributes )
            {
                try
                {
                    if ( !containsAttribute( schemaManager.lookupAttributeTypeRegistry( attribute ) ) )
                    {
                        return false;
                    }
                }
                catch ( LdapException ne )
                {
                    return false;
                }
            }

            return true;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean containsAttribute( AttributeType attributeType )
    {
        if ( attributeType == null )
        {
            return false;
        }

        return attributes.containsKey( attributeType.getOid() );
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( AttributeType attributeType, byte[]... values )
    {
        if ( attributeType == null )
        {
            return false;
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            return attribute.contains( values );
        }
        else
        {
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( AttributeType attributeType, String... values )
    {
        if ( attributeType == null )
        {
            return false;
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            return attribute.contains( values );
        }
        else
        {
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( AttributeType attributeType, Value<?>... values )
    {
        if ( attributeType == null )
        {
            return false;
        }

        Attribute attribute = attributes.get( attributeType.getOid() );

        if ( attribute != null )
        {
            return attribute.contains( values );
        }
        else
        {
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( String upId, byte[]... values )
    {
        if ( Strings.isEmpty( upId ) )
        {
            return false;
        }

        String id = getId( upId );

        if ( schemaManager != null )
        {
            try
            {
                return contains( schemaManager.lookupAttributeTypeRegistry( id ), values );
            }
            catch ( LdapException le )
            {
                return false;
            }
        }

        Attribute attribute = attributes.get( id );

        if ( attribute == null )
        {
            return false;
        }

        return attribute.contains( values );
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( String upId, String... values )
    {
        if ( Strings.isEmpty( upId ) )
        {
            return false;
        }

        String id = getId( upId );

        if ( schemaManager != null )
        {
            try
            {
                return contains( schemaManager.lookupAttributeTypeRegistry( id ), values );
            }
            catch ( LdapException le )
            {
                return false;
            }
        }

        Attribute attribute = attributes.get( id );

        if ( attribute == null )
        {
            return false;
        }

        return attribute.contains( values );
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( String upId, Value<?>... values )
    {
        if ( Strings.isEmpty( upId ) )
        {
            return false;
        }

        String id = getId( upId );

        if ( schemaManager != null )
        {
            try
            {
                return contains( schemaManager.lookupAttributeTypeRegistry( id ), values );
            }
            catch ( LdapException le )
            {
                return false;
            }
        }

        Attribute attribute = attributes.get( id );

        if ( attribute == null )
        {
            return false;
        }

        return attribute.contains( values );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute get( String alias )
    {
        try
        {
            String id = getId( alias );

            if ( schemaManager != null )
            {
                try
                {
                    AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry( id );

                    return attributes.get( attributeType.getOid() );
                }
                catch ( LdapException ne )
                {
                    String message = ne.getLocalizedMessage();
                    LOG.error( message );
                    return null;
                }
            }
            else
            {
                return attributes.get( id );
            }
        }
        catch ( IllegalArgumentException iea )
        {
            LOG.error( I18n.err( I18n.ERR_04134, alias ) );
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    public Attribute get( AttributeType attributeType )
    {
        if ( attributeType != null )
        {
            return attributes.get( attributeType.getOid() );
        }
        else
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    public Collection<Attribute> getAttributes()
    {
        return Collections.unmodifiableMap( attributes ).values();
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, byte[]... values )
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        if ( schemaManager == null )
        {
            // Get the normalized form of the ID
            String id = getId( upId );

            // Create a new attribute
            Attribute clientAttribute = new DefaultAttribute( upId, values );

            // Replace the previous one, and return it back
            return attributes.put( id, clientAttribute );
        }
        else
        {
            try
            {
                return put( upId, getAttributeType( upId ), values );
            }
            catch ( LdapException ne )
            {
                String message = I18n.err( I18n.ERR_04464, upId, ne.getLocalizedMessage() );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, String... values )
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        if ( schemaManager == null )
        {
            // Get the normalized form of the ID
            String id = getId( upId );

            // Create a new attribute
            Attribute clientAttribute = new DefaultAttribute( upId, values );

            // Replace the previous one, and return it back
            return attributes.put( id, clientAttribute );
        }
        else
        {
            try
            {
                return put( upId, getAttributeType( upId ), values );
            }
            catch ( LdapException ne )
            {
                String message = I18n.err( I18n.ERR_04464, upId, ne.getLocalizedMessage() );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, Value<?>... values )
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.error( message );
            throw new IllegalArgumentException( message );
        }

        if ( schemaManager == null )
        {
            // Get the normalized form of the ID
            String id = getId( upId );

            // Create a new attribute
            Attribute clientAttribute = new DefaultAttribute( upId, values );

            // Replace the previous one, and return it back
            return attributes.put( id, clientAttribute );
        }
        else
        {
            try
            {
                return put( upId, getAttributeType( upId ), values );
            }
            catch ( LdapException ne )
            {
                String message = I18n.err( I18n.ERR_04464, upId, ne.getLocalizedMessage() );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }
        }
    }


    /**
     * {@inheritDoc}
     **
    public List<Attribute> set( AttributeType... attributeTypes )
    {
        List<Attribute> removed = new ArrayList<Attribute>();

        // Now, loop on all the attributeType to add
        for ( AttributeType attributeType : attributeTypes )
        {
            if ( attributeType == null )
            {
                String message = I18n.err( I18n.ERR_04467 );
                LOG.error( message );
                continue;
            }

            Attribute attribute = attributes.put( attributeType.getOid(),
                new DefaultAttribute( attributeType ) );

            if ( attribute != null )
            {
                removed.add( attribute );
            }
        }

        if ( removed.size() == 0 )
        {
            return null;
        }
        else
        {
            return removed;
        }
    }


    /**
     * {@inheritDoc}
     */
    public List<Attribute> put( Attribute... attributes ) throws LdapException
    {
        // First, get the existing attributes
        List<Attribute> previous = new ArrayList<Attribute>();

        if ( schemaManager == null )
        {
            for ( Attribute attribute : attributes )
            {
                String id = attribute.getId();

                if ( containsAttribute( id ) )
                {
                    // Store the attribute and remove it from the list
                    previous.add( get( id ) );
                    this.attributes.remove( id );
                }

                // add the new one
                this.attributes.put( id, attribute );
            }
        }
        else
        {
            for ( Attribute attribute : attributes )
            {
                if ( attribute == null )
                {
                    String message = I18n.err( I18n.ERR_04462 );
                    LOG.error( message );
                    throw new IllegalArgumentException( message );
                }

                if ( attribute.getAttributeType() == null )
                {
                    AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry( attribute.getId() );
                    attribute.apply( attributeType );
                }

                Attribute removed = this.attributes.put( attribute.getAttributeType().getOid(), attribute );

                if ( removed != null )
                {
                    previous.add( removed );
                }
            }
        }

        // return the previous attributes
        return previous;
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( AttributeType attributeType, byte[]... values ) throws LdapException
    {
        return put( null, attributeType, values );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( AttributeType attributeType, String... values ) throws LdapException
    {
        return put( null, attributeType, values );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        return put( null, attributeType, values );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, AttributeType attributeType, byte[]... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            try
            {
                attributeType = getAttributeType( upId );
            }
            catch ( Exception e )
            {
                String message = I18n.err( I18n.ERR_04477_NO_VALID_AT_FOR_THIS_ID );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }
        }
        else
        {
            if ( !Strings.isEmpty( upId ) )
            {
                AttributeType tempAT = getAttributeType( upId );

                if ( !tempAT.equals( attributeType ) )
                {
                    String message = I18n.err( I18n.ERR_04463, upId, attributeType );
                    LOG.error( message );
                    throw new IllegalArgumentException( message );
                }
            }
            else
            {
                upId = getUpId( upId, attributeType );
            }
        }

        if ( attributeType.equals( objectClassAttributeType ) )
        {
            String message = I18n.err( I18n.ERR_04461 );
            LOG.error( message );
            throw new UnsupportedOperationException( message );
        }

        Attribute attribute = new DefaultAttribute( upId, attributeType, values );

        return attributes.put( attributeType.getOid(), attribute );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, AttributeType attributeType, String... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            try
            {
                attributeType = getAttributeType( upId );
            }
            catch ( Exception e )
            {
                String message = I18n.err( I18n.ERR_04477_NO_VALID_AT_FOR_THIS_ID );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }
        }
        else
        {
            if ( !Strings.isEmpty( upId ) )
            {
                AttributeType tempAT = getAttributeType( upId );

                if ( !tempAT.equals( attributeType ) )
                {
                    String message = I18n.err( I18n.ERR_04463, upId, attributeType );
                    LOG.error( message );
                    throw new IllegalArgumentException( message );
                }
            }
            else
            {
                upId = getUpId( upId, attributeType );
            }
        }

        Attribute attribute = new DefaultAttribute( upId, attributeType, values );

        return attributes.put( attributeType.getOid(), attribute );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            try
            {
                attributeType = getAttributeType( upId );
            }
            catch ( Exception e )
            {
                String message = I18n.err( I18n.ERR_04477_NO_VALID_AT_FOR_THIS_ID );
                LOG.error( message );
                throw new IllegalArgumentException( message );
            }
        }
        else
        {
            if ( !Strings.isEmpty( upId ) )
            {
                AttributeType tempAT = getAttributeType( upId );

                if ( !tempAT.equals( attributeType ) )
                {
                    String message = I18n.err( I18n.ERR_04463, upId, attributeType );
                    LOG.error( message );
                    throw new IllegalArgumentException( message );
                }
            }
            else
            {
                upId = getUpId( upId, attributeType );
            }
        }

        Attribute attribute = new DefaultAttribute( upId, attributeType, values );

        return attributes.put( attributeType.getOid(), attribute );
    }


    /**
     * {@inheritDoc}
     */
    public List<Attribute> remove( Attribute... attributes ) throws LdapException
    {
        List<Attribute> removedAttributes = new ArrayList<Attribute>();

        if ( schemaManager == null )
        {
            for ( Attribute attribute : attributes )
            {
                if ( containsAttribute( attribute.getId() ) )
                {
                    this.attributes.remove( attribute.getId() );
                    removedAttributes.add( attribute );
                }
            }
        }
        else
        {
            for ( Attribute attribute : attributes )
            {
                AttributeType attributeType = attribute.getAttributeType();

                if ( attributeType == null )
                {
                    String message = I18n.err( I18n.ERR_04460_ATTRIBUTE_TYPE_NULL_NOT_ALLOWED );
                    LOG.error( message );
                    throw new IllegalArgumentException( message );
                }

                if ( this.attributes.containsKey( attributeType.getOid() ) )
                {
                    this.attributes.remove( attributeType.getOid() );
                    removedAttributes.add( attribute );
                }
            }
        }

        return removedAttributes;
    }


    /**
     * {@inheritDoc}
     */
    public boolean remove( AttributeType attributeType, byte[]... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            return false;
        }

        try
        {
            Attribute attribute = attributes.get( attributeType.getOid() );

            if ( attribute == null )
            {
                // Can't remove values from a not existing attribute !
                return false;
            }

            int nbOldValues = attribute.size();

            // Remove the values
            attribute.remove( values );

            if ( attribute.size() == 0 )
            {
                // No mare values, remove the attribute
                attributes.remove( attributeType.getOid() );

                return true;
            }

            return nbOldValues != attribute.size();
        }
        catch ( IllegalArgumentException iae )
        {
            LOG.error( I18n.err( I18n.ERR_04465, attributeType ) );
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean remove( AttributeType attributeType, String... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            return false;
        }

        try
        {
            Attribute attribute = attributes.get( attributeType.getOid() );

            if ( attribute == null )
            {
                // Can't remove values from a not existing attribute !
                return false;
            }

            int nbOldValues = attribute.size();

            // Remove the values
            attribute.remove( values );

            if ( attribute.size() == 0 )
            {
                // No mare values, remove the attribute
                attributes.remove( attributeType.getOid() );

                return true;
            }

            return nbOldValues != attribute.size();
        }
        catch ( IllegalArgumentException iae )
        {
            LOG.error( I18n.err( I18n.ERR_04465, attributeType ) );
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    public boolean remove( AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        if ( attributeType == null )
        {
            return false;
        }

        try
        {
            Attribute attribute = attributes.get( attributeType.getOid() );

            if ( attribute == null )
            {
                // Can't remove values from a not existing attribute !
                return false;
            }

            int nbOldValues = attribute.size();

            // Remove the values
            attribute.remove( values );

            if ( attribute.size() == 0 )
            {
                // No mare values, remove the attribute
                attributes.remove( attributeType.getOid() );

                return true;
            }

            return nbOldValues != attribute.size();
        }
        catch ( IllegalArgumentException iae )
        {
            LOG.error( I18n.err( I18n.ERR_04465, attributeType ) );
            return false;
        }
    }


    /**
     * <p>
     * Removes the attribute with the specified AttributeTypes.
     * </p>
     * <p>
     * The removed attribute are returned by this method.
     * </p>
     * <p>
     * If there is no attribute with the specified AttributeTypes,
     * the return value is <code>null</code>.
     * </p>
     *
     * @param attributes the AttributeTypes to be removed
     * @return the removed attributes, if any, as a list; otherwise <code>null</code>
     */
    public void removeAttributes( AttributeType... attributes )
    {
        if ( ( attributes == null ) || ( attributes.length == 0 ) || ( schemaManager == null ) )
        {
            return;
        }

        for ( AttributeType attributeType : attributes )
        {
            if ( attributeType == null )
            {
                continue;
            }

            this.attributes.remove( attributeType.getOid() );
        }
    }


    /**
     * {@inheritDoc}
     */
    public void removeAttributes( String... attributes )
    {
        if ( attributes.length == 0 )
        {
            return;
        }

        if ( schemaManager == null )
        {
            for ( String attribute : attributes )
            {
                Attribute attr = get( attribute );

                if ( attr != null )
                {
                    this.attributes.remove( attr.getId() );
                }
                else
                {
                    String message = I18n.err( I18n.ERR_04137, attribute );
                    LOG.warn( message );
                    continue;
                }
            }
        }
        else
        {
            for ( String attribute : attributes )
            {
                AttributeType attributeType = null;

                try
                {
                    attributeType = schemaManager.lookupAttributeTypeRegistry( attribute );
                }
                catch ( LdapException ne )
                {
                    String message = "The attribute '" + attribute + "' does not exist in the entry";
                    LOG.warn( message );
                    continue;
                }

                this.attributes.remove( attributeType.getOid() );
            }
        }
    }


    /**
     * <p>
     * Removes the specified binary values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after having removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns
     * <code>false</code>
     * </p>
     *
     * @param upId The attribute ID
     * @param values the values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist.
     */
    public boolean remove( String upId, byte[]... values ) throws LdapException
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.info( message );
            return false;
        }

        if ( schemaManager == null )
        {
            String id = getId( upId );

            Attribute attribute = get( id );

            if ( attribute == null )
            {
                // Can't remove values from a not existing attribute !
                return false;
            }

            int nbOldValues = attribute.size();

            // Remove the values
            attribute.remove( values );

            if ( attribute.size() == 0 )
            {
                // No mare values, remove the attribute
                attributes.remove( id );

                return true;
            }

            return nbOldValues != attribute.size();
        }
        else
        {
            try
            {
                AttributeType attributeType = getAttributeType( upId );

                return remove( attributeType, values );
            }
            catch ( LdapException ne )
            {
                LOG.error( I18n.err( I18n.ERR_04465, upId ) );
                return false;
            }
            catch ( IllegalArgumentException iae )
            {
                LOG.error( I18n.err( I18n.ERR_04466, upId ) );
                return false;
            }
        }

    }


    /**
     * <p>
     * Removes the specified String values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after having removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns
     * <code>false</code>
     * </p>
     *
     * @param upId The attribute ID
     * @param values the attributes to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist.
     */
    public boolean remove( String upId, String... values ) throws LdapException
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.info( message );
            return false;
        }

        if ( schemaManager == null )
        {
            String id = getId( upId );

            Attribute attribute = get( id );

            if ( attribute == null )
            {
                // Can't remove values from a not existing attribute !
                return false;
            }

            int nbOldValues = attribute.size();

            // Remove the values
            attribute.remove( values );

            if ( attribute.size() == 0 )
            {
                // No mare values, remove the attribute
                attributes.remove( id );

                return true;
            }

            return nbOldValues != attribute.size();
        }
        else
        {
            try
            {
                AttributeType attributeType = getAttributeType( upId );

                return remove( attributeType, values );
            }
            catch ( LdapException ne )
            {
                LOG.error( I18n.err( I18n.ERR_04465, upId ) );
                return false;
            }
            catch ( IllegalArgumentException iae )
            {
                LOG.error( I18n.err( I18n.ERR_04466, upId ) );
                return false;
            }
        }
    }


    /**
     * <p>
     * Removes the specified values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after having removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns
     * <code>false</code>
     * </p>
     *
     * @param upId The attribute ID
     * @param values the attributes to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist.
     */
    public boolean remove( String upId, Value<?>... values ) throws LdapException
    {
        if ( Strings.isEmpty( upId ) )
        {
            String message = I18n.err( I18n.ERR_04457_NULL_ATTRIBUTE_ID );
            LOG.info( message );
            return false;
        }

        if ( schemaManager == null )
        {
            String id = getId( upId );

            Attribute attribute = get( id );

            if ( attribute == null )
            {
                // Can't remove values from a not existing attribute !
                return false;
            }

            int nbOldValues = attribute.size();

            // Remove the values
            attribute.remove( values );

            if ( attribute.size() == 0 )
            {
                // No mare values, remove the attribute
                attributes.remove( id );

                return true;
            }

            return nbOldValues != attribute.size();
        }
        else
        {
            try
            {
                AttributeType attributeType = getAttributeType( upId );

                return remove( attributeType, values );
            }
            catch ( LdapException ne )
            {
                LOG.error( I18n.err( I18n.ERR_04465, upId ) );
                return false;
            }
            catch ( IllegalArgumentException iae )
            {
                LOG.error( I18n.err( I18n.ERR_04466, upId ) );
                return false;
            }
        }
    }


    /**
     * Get this entry's Dn.
     *
     * @return The entry's Dn
     */
    public Dn getDn()
    {
        return dn;
    }


    /**
     * {@inheritDoc}
     */
    public void setDn( Dn dn )
    {
        this.dn = dn;

        // Rehash the object
        rehash();
    }


    /**
     * {@inheritDoc}
     */
    public void setDn( String dn ) throws LdapInvalidDnException
    {
        setDn( new Dn( dn ) );
    }


    /**
     * Remove all the attributes for this entry. The Dn is not reset
     */
    public void clear()
    {
        attributes.clear();
    }


    /**
     * Returns an enumeration containing the zero or more attributes in the
     * collection. The behavior of the enumeration is not specified if the
     * attribute collection is changed.
     *
     * @return an enumeration of all contained attributes
     */
    public Iterator<Attribute> iterator()
    {
        return Collections.unmodifiableMap( attributes ).values().iterator();
    }


    /**
     * Returns the number of attributes.
     *
     * @return the number of attributes
     */
    public int size()
    {
        return attributes.size();
    }


    /**
     * This is the place where we serialize entries, and all theirs
     * elements.
     * <br/>
     * The structure used to store the entry is the following :
     * <ul>
     *   <li>
     *     <b>[Dn]</b> : If it's null, stores an empty Dn
     *   </li>
     *   <li>
     *     <b>[attributes number]</b> : the number of attributes.
     *   </li>
     *   <li>
     *     <b>[attribute]*</b> : each attribute, if we have some
     *   </li>
     * </ul>
     * 
     * {@inheritDoc}
     */
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        // First, the Dn
        if ( dn == null )
        {
            // Write an empty Dn
            Dn.EMPTY_DN.writeExternal( out );
        }
        else
        {
            // Write the Dn
            dn.writeExternal( out );
        }

        // Then the attributes.
        // Store the attributes' nulber first
        out.writeInt( attributes.size() );

        // Iterate through the keys.
        for ( Attribute attribute : attributes.values() )
        {
            // Store the attribute
            attribute.writeExternal( out );
        }

        out.flush();
    }


    /**
     * {@inheritDoc}
     */
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        // Read the Dn
        dn = new Dn( schemaManager );
        dn.readExternal( in );

        // Read the number of attributes
        int nbAttributes = in.readInt();

        // Read the attributes
        for ( int i = 0; i < nbAttributes; i++ )
        {
            // Read each attribute
            Attribute attribute = new DefaultAttribute();
            attribute.readExternal( in );

            if ( schemaManager != null )
            {
                try
                {
                    AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry( attribute.getId() );
                    attribute.apply( attributeType );

                    attributes.put( attributeType.getOid(), attribute );
                }
                catch ( LdapException le )
                {
                    String message = le.getLocalizedMessage();
                    LOG.error( message );
                    throw new IOException( message );
                }
            }
            else
            {
                attributes.put( attribute.getId(), attribute );
            }
        }
    }


    /**
     * Get the hash code of this ClientEntry. The Attributes will be sorted
     * before the comparison can be done.
     *
     * @see java.lang.Object#hashCode()
     * @return the instance's hash code
     */
    public int hashCode()
    {
        if ( h == 0 )
        {
            rehash();
        }

        return h;
    }


    /**
     * {@inheritDoc}
     */
    public boolean hasObjectClass( String... objectClasses )
    {
        if ( ( objectClasses == null ) || ( objectClasses.length == 0 ) || ( objectClasses[0] == null ) )
        {
            return false;
        }

        for ( String objectClass : objectClasses )
        {
            if ( schemaManager != null )
            {
                if ( !contains( objectClassAttributeType, objectClass ) )
                {
                    return false;
                }
            }
            else
            {
                if ( !contains( "objectclass", objectClass ) )
                {
                    return false;
                }
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    public boolean hasObjectClass( Attribute... objectClasses )
    {
        if ( ( objectClasses == null ) || ( objectClasses.length == 0 ) || ( objectClasses[0] == null ) )
        {
            return false;
        }

        for ( Attribute objectClass : objectClasses )
        {
            // We have to check that we are checking the ObjectClass attributeType
            if ( !objectClass.getAttributeType().equals( objectClassAttributeType ) )
            {
                return false;
            }

            Attribute attribute = attributes.get( objectClassAttributeType.getOid() );

            if ( attribute == null )
            {
                // The entry does not have an ObjectClass attribute
                return false;
            }

            for ( Value<?> value : objectClass )
            {
                // Loop on all the values, and check if they are present
                if ( !attribute.contains( value.getString() ) )
                {
                    return false;
                }
            }
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    public boolean isSchemaAware()
    {
        return schemaManager != null;
    }


    /**
     * @see Object#equals(Object)
     */
    public boolean equals( Object o )
    {
        // Short circuit
        if ( this == o )
        {
            return true;
        }

        if ( !( o instanceof Entry ) )
        {
            return false;
        }

        Entry other = ( Entry ) o;

        // Both Dn must be equal
        if ( dn == null )
        {
            if ( other.getDn() != null )
            {
                return false;
            }
        }
        else
        {
            if ( !dn.equals( other.getDn() ) )
            {
                return false;
            }
        }

        // They must have the same number of attributes
        if ( size() != other.size() )
        {
            return false;
        }

        // Each attribute must be equal
        for ( Attribute attribute : other )
        {
            if ( !attribute.equals( this.get( attribute.getId() ) ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * @see Object#toString()
     */
    public String toString()
    {
        return toString( "" );
    }


    /**
     * {@inheritDoc}
     */
    public String toString( String tabs )
    {
        StringBuilder sb = new StringBuilder();

        sb.append( tabs ).append( "Entry\n" );
        sb.append( tabs ).append( "    dn" );

        if ( dn.isSchemaAware() )
        {
            sb.append( "[n]" );
        }

        sb.append( ": " );
        sb.append( dn.getName() );
        sb.append( '\n' );

        // First dump the ObjectClass attribute
        if ( schemaManager != null )
        {
            // First dump the ObjectClass attribute
            if ( containsAttribute( objectClassAttributeType.getOid() ) )
            {
                Attribute objectClass = get( objectClassAttributeType );

                sb.append( objectClass.toString( tabs + "    " ) );
            }
        }
        else
        {
            if ( containsAttribute( "objectClass" ) )
            {
                Attribute objectClass = get( "objectclass" );

                sb.append( objectClass.toString( tabs + "    " ) );
            }
        }

        if ( attributes.size() != 0 )
        {
            for ( Attribute attribute : attributes.values() )
            {
                String id = attribute.getId();

                if ( schemaManager != null )
                {
                    AttributeType attributeType = schemaManager.getAttributeType( id );

                    if ( attributeType == null )
                    {
                        sb.append( tabs + "id: " + id );
                    }
                    else if ( !attributeType.equals( objectClassAttributeType ) )
                    {
                        sb.append( attribute.toString( tabs + "    " ) );
                        continue;
                    }
                }
                else
                {
                    if ( !id.equalsIgnoreCase( SchemaConstants.OBJECT_CLASS_AT )
                        && !id.equals( SchemaConstants.OBJECT_CLASS_AT_OID ) )
                    {
                        sb.append( attribute.toString( tabs + "    " ) );
                        continue;
                    }
                }
            }
        }

        return sb.toString();
    }
}
