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
package org.jboss.security.xacml.util;

import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.jboss.security.xacml.jaxb.Option;

/**
 * Common Utility class for LDAP integration
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @author Anil.Saldhana@redhat.com
 * @since Aug 25, 2010
 */
public class LDAPCommon
{
   private static Logger log = Logger.getLogger( LDAPCommon.class.getName() );

   public enum TYPE { POLICY, ATTRIBUTE };

   private static final String XACML_LDAP_URL = "url";

   private String url;

   private static final String XACML_LDAP_FACTORY = "factory";

   private String factory;

   private static final String XACML_LDAP_USERNAME = "username";

   private String username;

   private static final String XACML_LDAP_PASSWORD = "password";

   private String password;

   private static final String XACML_LDAP_FILTER = "filter";

   private String filter;

   private static final String XACML_LDAP_ATTRIBUTE = "attribute";

   private String attribute;

   private static final String XACML_LDAP_SEARCH_SCOPE = "searchScope";

   private int searchScope = SearchControls.SUBTREE_SCOPE;

   private static final String XACML_LDAP_SEARCH_TIMELIMIT = "searchTimeLimit";

   private int searchTimeLimit = 10000;

   private static final String XACML_LDAP_BASEDN = "baseDN";

   private String baseDN;

   private static final String XACML_LDAP_SALT = "salt";

   private String salt;

   private static final String XACML_LDAP_COUNT = "iterationCount";

   private int iterationCount;

   private static final String XACML_LDAP_PASSWORD_PREFIX = "MASK-";
   
   private static final String XACML_LDAP_ATTRIBUTE_SUPPORTED_ID = "attributeSupportedId";
   private String attributeSupportedId;
   
   private static final String XACML_LDAP_SUBSTITUTE_VALUE = "substituteValue";
   private String substituteValue;
   
   private static final String XACML_LDAP_VALUE_DATA_TYPE = "valueDataType";
   private String valueDataType;
   
   private Properties env = new Properties();

   private InitialLdapContext ctx = null;

   public void processOptions(List<Option> theoptions)
   {   
      for( Option option : theoptions )
      {
         processPassedOption( option.getName(), (String) option.getContent().iterator().next() );
      }

      fillInMissingConfigurationWithDefaults(); 
   }  

   public void processPassedOption( String optionTag, String optionValue) 
   {
      String name =optionTag;

      if (name.equals(XACML_LDAP_URL))
         url = optionValue;
      else if (name.equals(XACML_LDAP_FACTORY))
         factory = optionValue;
      else if (name.equals(XACML_LDAP_USERNAME))
         username = optionValue;
      else if (name.equals(XACML_LDAP_PASSWORD))
         password = optionValue;
      else if (name.equals(XACML_LDAP_FILTER))
         filter = optionValue;
      else if (name.equals(XACML_LDAP_ATTRIBUTE))
         attribute = optionValue;
      else if (name.equals(XACML_LDAP_BASEDN))
         baseDN = optionValue;
      else if (name.equals(XACML_LDAP_SEARCH_TIMELIMIT))
      {
         String timeLimit = optionValue;
         if (timeLimit != null)
         {
            try
            {
               searchTimeLimit = Integer.parseInt(timeLimit);
            }
            catch (NumberFormatException e)
            {
               log.fine("Failed to parse: " + timeLimit + ", using searchTimeLimit = " + searchTimeLimit + ". "
                     + e.getMessage());
            }
         }
      }
      else if (name.equals(XACML_LDAP_SEARCH_SCOPE))
      {
         String scope = optionValue;
         if ("OBJECT_SCOPE".equalsIgnoreCase(scope))
            searchScope = SearchControls.OBJECT_SCOPE;
         else if ("ONELEVEL_SCOPE".equalsIgnoreCase(scope))
            searchScope = SearchControls.ONELEVEL_SCOPE;
         if ("SUBTREE_SCOPE".equalsIgnoreCase(scope))
            searchScope = SearchControls.SUBTREE_SCOPE;
      }
      else if (name.equals(XACML_LDAP_SALT))
         salt = optionValue;
      else if (name.equals(XACML_LDAP_COUNT))
         iterationCount = Integer.parseInt( optionValue );
      else if (name.equals( XACML_LDAP_ATTRIBUTE_SUPPORTED_ID ))
         attributeSupportedId = optionValue;
      else if (name.equals( XACML_LDAP_SUBSTITUTE_VALUE ))
         substituteValue = optionValue;
      else if (name.equals( XACML_LDAP_VALUE_DATA_TYPE ))
            valueDataType = optionValue;
      else if( name.equals( "java.naming.factory.initial" ))
         factory = optionValue ;
      else if( name.equals( "java.naming.provider.url" ))
         url = optionValue;
   }

   /**
    * Validate that the configuration has all the required parameters
    * @param locatorType
    */
   public void validateConfiguration( TYPE locatorType )
   {
      // check options. username and password can be null as the ldap server may allow anonymous search
      if (url == null)
         throw new IllegalArgumentException("Option " + XACML_LDAP_URL + " cannot be null");
      if (filter == null)
         throw new IllegalArgumentException("Option " + XACML_LDAP_FILTER + " cannot be null");
      if (attribute == null)
         throw new IllegalArgumentException("Option " + XACML_LDAP_ATTRIBUTE + " cannot be null"); 

      if( locatorType == TYPE.ATTRIBUTE )
      {
         if( valueDataType == null )
            throw new IllegalArgumentException("Option " + XACML_LDAP_VALUE_DATA_TYPE + " cannot be null");
         if( attributeSupportedId == null )
            throw new IllegalArgumentException("Option " + XACML_LDAP_ATTRIBUTE_SUPPORTED_ID + " cannot be null");
         if( substituteValue == null )
            throw new IllegalArgumentException("Option " + XACML_LDAP_SUBSTITUTE_VALUE + " cannot be null");
      }
   }

   /**
    * Get the attribute name that we are interested in
    * Examples include cn, uid, employeeType
    * @return
    */
   public String getLdapAttribute()
   {
      return attribute;
   } 
   
   /**
    * Get the XML Data Type of the value that we are going to substitute
    * in the wild card of the filter during searching
    * 
    * The value will be picked up from the xacml request
    * @return
    */
   public String getDataTypeOfSubstituteValue()
   {
      return this.valueDataType;
   } 

   /**
    * The namespace of the value that we are going to pick up
    * from the xacml request to be substituted in the wildcard
    * for the ldap search filter
    * @return
    */
   public String getSubsititeValue()
   {
       return substituteValue;
   }

   /**
    * Perform a search
    * 
    * The {@code LDAPAttributeLocator} will always send a filterArg array
    * 
    * @param filterArgs can be null. Contains the wildcard substitution for the filter
    * @return
    * @throws NamingException
    */
   public NamingEnumeration<SearchResult> search( Object[] filterArgs ) throws NamingException
   {
      InitialLdapContext ctx = new InitialLdapContext(env, null);

      SearchControls constraints = new SearchControls();
      constraints.setSearchScope(searchScope);
      constraints.setTimeLimit(searchTimeLimit);
      constraints.setReturningAttributes(new String[] { attribute }); //The attribute we are looking for 

      if( filterArgs != null )
         return ctx.search( baseDN, filter, filterArgs, constraints );
         
      return  ctx.search(baseDN, filter, constraints); 
   }

   /**
    * Construct the JNDI Context. Must always be in a try/catch/finally
    * @see {@link #closeJNDIContext()}
    * @throws NamingException
    */
   public void constructJNDIContext() throws NamingException
   {
      if (password != null && password.startsWith(XACML_LDAP_PASSWORD_PREFIX))
      {
         // try to decode password
         if (salt == null || salt.equals("") || salt.length() != 8)
            throw new IllegalArgumentException("Option " + XACML_LDAP_SALT + " is not set correctly");
         if (iterationCount == 0)
            throw new IllegalArgumentException("Option " + XACML_LDAP_COUNT + " must be a positive integer");
         password = decodePassword(password);
      }

      env.put(Context.INITIAL_CONTEXT_FACTORY, factory );
      env.put(Context.PROVIDER_URL, url);
      if (username != null)
         env.put(Context.SECURITY_PRINCIPAL, username);
      if (password != null)
         env.put(Context.SECURITY_CREDENTIALS, password);

      ctx = new InitialLdapContext( env, null );
   }

   /**
    * Close the JNDI Context
    * @throws NamingException
    */
   public void closeJNDIContext() throws NamingException
   {
      if( ctx != null )
         ctx.close(); 
   }

   /**
    * If any configuration is missing and we know some defaults, use that
    */
   private void fillInMissingConfigurationWithDefaults()
   {
      if( factory == null )
         factory = "com.sun.jndi.ldap.LdapCtxFactory";
   }

   private String decodePassword(String encodedPassword)
   {
      try
      {
         // remove prefix
         String password = encodedPassword.substring(XACML_LDAP_PASSWORD_PREFIX.length());
         byte[] salt = this.salt.getBytes();
         char[] p = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
         PBEParameterSpec cipherSpec = new PBEParameterSpec(salt, iterationCount);
         PBEKeySpec keySpec = new PBEKeySpec(p);
         String cipherAlgorithm = "PBEwithMD5andDES";
         SecretKeyFactory factory = SecretKeyFactory.getInstance(cipherAlgorithm);
         SecretKey cipherKey = factory.generateSecret(keySpec);
         //TODO move these utils to a separate project
         return PBEUtils.decode64(password, cipherAlgorithm, cipherKey, cipherSpec);
      }
      catch (Exception e)
      {
         log.severe("Could not decode masked password. " + e.getMessage());
         throw new IllegalStateException(e);
      }
   }
}