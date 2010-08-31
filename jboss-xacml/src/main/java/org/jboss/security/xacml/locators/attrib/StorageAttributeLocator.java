/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.security.xacml.locators.attrib;

import java.net.URI;
import java.net.URISyntaxException;

import org.jboss.security.xacml.locators.AttributeLocator;
import org.jboss.security.xacml.sunxacml.EvaluationCtx; 

/**
 * Common base class for attribute locators using external storage
 * 
 * All subclasses have to override and implement the
 *  {@link #findAttribute(URI, URI, URI, URI, EvaluationCtx, int)} method
 *  
 * @author Anil.Saldhana@redhat.com
 * @since Aug 25, 2010
 */
public abstract class StorageAttributeLocator extends AttributeLocator
{
   //The data type of the attribute value that we are substituting in
   //prepared statement or ldap query
   protected String dataTypeOfSubstituteValue = null;
   
   /**
    * Represents an URI that we will use to pick from the xacml
    * request to substitute in a DB prepared statement or ldap DN
    * to authenticate/identify the target/person/employee we are trying
    * to get an attribute for.
    */
   protected String substituteValue = null;
   
   //The value of the attribute we are seeking
   protected Object attributeValue = null;
 
   public StorageAttributeLocator()
   {
      this.attributeDesignatorSupported = true;
      this.attributeSelectorSupported = true;
      
      this.designatorTypes.add(Integer.valueOf(0));
      this.designatorTypes.add(Integer.valueOf(1));
      this.designatorTypes.add(Integer.valueOf(2));
   }  
   
   /**
    * For locators based on DB or LDAP, we may need one value that needs to be substituted in the DB prepared
    * statement or ldap DIT query.  This value for example, can be the uid
    * 
    * @param attributeType
    * @param context
    * @return
    * @throws URISyntaxException
    */
   protected abstract Object getSubstituteValue( URI attributeType, EvaluationCtx context ) throws URISyntaxException;
}