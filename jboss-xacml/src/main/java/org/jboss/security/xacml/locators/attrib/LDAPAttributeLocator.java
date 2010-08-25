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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.attr.BagAttribute;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.jboss.security.xacml.util.JBossXACMLUtil;
import org.jboss.security.xacml.util.LDAPCommon;

/**
 * An attribute locator getting attribute values from an LDAP
 * @author Anil.Saldhana@redhat.com
 * @since Aug 25, 2010
 */
public abstract class LDAPAttributeLocator extends StorageAttributeLocator
{ 
   private static Logger log = Logger.getLogger( LDAPAttributeLocator.class.getName() );
   
   protected LDAPCommon ldapCommon = new LDAPCommon();
   
   public LDAPAttributeLocator()
   {
      this.attributeDesignatorSupported = true;
      this.attributeSelectorSupported = true;
      
      this.designatorTypes.add(Integer.valueOf(0));
      this.designatorTypes.add(Integer.valueOf(1));
      this.designatorTypes.add(Integer.valueOf(2));
   }
   
   @Override
   public void setOptions(List<Option> theoptions)
   {
      super.setOptions(theoptions);
      ldapCommon.processOptions(theoptions);
      
      ldapCommon.validateConfiguration( LDAPCommon.TYPE.ATTRIBUTE );
   }
    
   @Override
   public EvaluationResult findAttribute(URI attributeType, URI attributeId, URI issuer, URI subjectCategory,
         EvaluationCtx context, int designatorType)
   { 
      if(ids.contains(attributeId) == false) 
      {
         if(attributeType != null)
            return new EvaluationResult(BagAttribute.createEmptyBag(attributeType));
         else

            return new EvaluationResult(BagAttribute.createEmptyBag(attributeId)); 
      }
      
      this.dataTypeOfSubstituteValue = ldapCommon.getDataTypeOfSubstituteValue();
      this.substituteValue = ldapCommon.getSubsititeValue();
 
      Object columnValue = null ;
      try
      {
         columnValue = getSubstituteValue( attributeType, context );
      }
      catch (URISyntaxException e)
      {
         log.log( Level.SEVERE, "Syntax error in uri:", e );
      }
      
      Object[] filterArgs = new Object[] { columnValue };
      
      NamingEnumeration<SearchResult> results = null;

      try
      { 
         ldapCommon.constructJNDIContext(); 
         
         results = ldapCommon.search( filterArgs ); 
         while (results.hasMore())
         {
            SearchResult rs = results.next();
            Attributes attributes = rs.getAttributes();
            if (attributes != null)
            {
               Attribute ldapAttribute = attributes.get( ldapCommon.getLdapAttribute() );
               if (ldapAttribute != null)
               {
                  attributeValue = ldapAttribute.get(); 
              }
            }
         }  
      }
      catch (NamingException e)
      {
         log.severe(e.getMessage());
         throw new IllegalStateException(e);
      }
      finally
      {
         if( results != null )
         {
            try {   results.close(); } catch ( NamingException ignore ) {}
         }

         try {  ldapCommon.closeJNDIContext(); }  catch (NamingException ignore ) {} 
      }
       
      Set<AttributeValue> bagSet = new HashSet<AttributeValue>();
      bagSet.add( JBossXACMLUtil.getAttributeValue( attributeValue ) );
      
      return new EvaluationResult( new BagAttribute( attributeType, bagSet )); 
   }

   @Override
   protected void usePassedOption(String optionTag, String optionValue)
   {
      super.usePassedOption(optionTag, optionValue);
      ldapCommon.processPassedOption(optionTag, optionValue); 
   }   
}