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
package org.jboss.security.xacml.locators;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;

import org.jboss.security.xacml.bridge.PolicySetFinderModule;
import org.jboss.security.xacml.bridge.WrapperPolicyFinderModule;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicySet;

/**
 * 
 * A PolicyLocator that searches for XACML policies and policy sets stored in an attribute of LDAP entries
 * The attribute contains the XACML policy as if the xml would be converted to a String.
 * This PolicyLocator is configured with the following options:
 * 
 * url - The LDAP server URL to connect to
 * username - The username to connect to the LDAP server. This user must have search privileges
 * password - The password of the user to connect to the LDAP server
 * filter - The search filter to be used to find the entries that have a policy
 * attribute - The name of the entry's attribute containing the XACML policy in the xml format
 * searchScope - Scope of the search for entries. Default is SUBTREE
 * searchTimeLimit - Search time limit. Default is 10000 (10 seconds)
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class JBossLDAPPolicyLocator extends AbstractJBossPolicyLocator
{

   protected static final String XACML_LDAP_URL = "url";

   protected String url;

   protected static final String XACML_LDAP_USERNAME = "username";

   protected String username;

   protected static final String XACML_LDAP_PASSWORD = "password";

   protected String password;

   protected static final String XACML_LDAP_FILTER = "filter";

   protected String filter;

   protected static final String XACML_LDAP_ATTRIBUTE = "attribute";

   protected String attribute;
   
   protected static final String XACML_LDAP_SEARCH_SCOPE = "searchScope";
   
   protected int searchScope = SearchControls.SUBTREE_SCOPE;
   
   protected static final String XACML_LDAP_SEARCH_TIMELIMIT = "searchTimeLimit";
   
   protected int searchTimeLimit = 10000;
   
   protected static final String XACML_LDAP_BASEDN = "baseDN";
   
   protected String baseDN;
   
   protected Properties env = new Properties();
   
   protected static Logger log = Logger.getLogger(JBossLDAPPolicyLocator.class.getName());
   
   public JBossLDAPPolicyLocator()
   {
   }

   @Override
   public void setPolicies(Set<XACMLPolicy> policies)
   {
   }

   @Override
   public void setOptions(List<Option> theoptions)
   {
      super.setOptions(theoptions);

      for (Option option : options)
      {
         String name = option.getName();
         if (name.equals(XACML_LDAP_URL))
            url = (String) option.getContent().iterator().next();
         else if (name.equals(XACML_LDAP_USERNAME))
            username = (String) option.getContent().iterator().next();
         else if (name.equals(XACML_LDAP_PASSWORD))
            password = (String) option.getContent().iterator().next();
         else if (name.equals(XACML_LDAP_FILTER))
            filter = (String) option.getContent().iterator().next();
         else if (name.equals(XACML_LDAP_ATTRIBUTE))
            attribute = (String) option.getContent().iterator().next();
         else if (name.equals(XACML_LDAP_BASEDN))
            baseDN = (String) option.getContent().iterator().next();
         else if (name.equals(XACML_LDAP_SEARCH_TIMELIMIT))
         {
            String timeLimit = (String) option.getContent().iterator().next();
            if (timeLimit != null)
            {
               try
               {
                  searchTimeLimit = Integer.parseInt(timeLimit);
               }
               catch (NumberFormatException e)
               {
                  log.fine("Failed to parse: " + timeLimit + ", using searchTimeLimit = " + searchTimeLimit + ". " + e.getMessage());
               }
            }
         }
         else if (name.equals(XACML_LDAP_SEARCH_SCOPE))
         {
            String scope = (String) option.getContent().iterator().next();
            if ("OBJECT_SCOPE".equalsIgnoreCase(scope))
               searchScope = SearchControls.OBJECT_SCOPE;
            else if ("ONELEVEL_SCOPE".equalsIgnoreCase(scope))
               searchScope = SearchControls.ONELEVEL_SCOPE;
            if ("SUBTREE_SCOPE".equalsIgnoreCase(scope))
               searchScope = SearchControls.SUBTREE_SCOPE;
         }
      }

      init();
   }

   protected void init()
   {
      // check options. username and password can be null as the ldap server may allow anonymous search
      if (url == null)
         throw new IllegalArgumentException("Option " + XACML_LDAP_URL + " cannot be null");
      if (filter == null)
         throw new IllegalArgumentException("Option " + XACML_LDAP_FILTER + " cannot be null");
      if (attribute == null)
         throw new IllegalArgumentException("Option " + XACML_LDAP_ATTRIBUTE + " cannot be null");
     
      env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
      env.put(Context.PROVIDER_URL, url);
      if (username != null)
         env.put(Context.SECURITY_PRINCIPAL, username);
      if (password != null)
         env.put(Context.SECURITY_CREDENTIALS, password);
      
      search();
   }
   
   protected void search()
   {
      InitialLdapContext ctx = null;
      NamingEnumeration<SearchResult> results = null;
      try
      {
         ctx = new InitialLdapContext(env, null);

         SearchControls constraints = new SearchControls();
         constraints.setSearchScope(searchScope);
         constraints.setTimeLimit(searchTimeLimit);
         constraints.setReturningAttributes(new String[]{attribute});
         
         results = ctx.search(baseDN, filter, constraints);
         while (results.hasMore())
         {
            SearchResult rs = results.next();
            Attributes attributes = rs.getAttributes();
            if (attributes != null)
            {
               Attribute xml = attributes.get(attribute);
               if (xml != null)
               {
                  String xmlString = (String) xml.get();
                  try
                  {
                     XACMLPolicy policy = PolicyFactory.createPolicy(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));
                     if (policy != null)
                     {
                        if (policy.getType() == XACMLPolicy.POLICY)
                        {
                           Policy p = policy.get(XACMLConstants.UNDERLYING_POLICY);
                           WrapperPolicyFinderModule wpfm = new WrapperPolicyFinderModule(p);
                           pfml.add(wpfm);
                        }
                        if (policy.getType() == XACMLPolicy.POLICYSET)
                        {
                           pfml.add(getPopulatedPolicySetFinderModule(policy));
                        }
                     }
                  }
                  catch (UnsupportedEncodingException e)
                  {
                     log.severe(e.getMessage());
                  }
                  catch (Exception e)
                  {
                     log.severe(e.getMessage());
                  }
               }
            }
         }
         this.map.put(XACMLConstants.POLICY_FINDER_MODULE, pfml);
      }
      catch (NamingException e)
      {
         log.severe(e.getMessage());
         throw new IllegalStateException(e);
      }
      finally
      {
         if (results != null)
         {
            try
            {
               results.close();
            }
            catch (NamingException e)
            {
            }
         }
         if (ctx != null)
         {
            try
            {
               ctx.close();
            }
            catch (NamingException e)
            {
            }
         }
      }
   }
   
   private PolicySetFinderModule getPopulatedPolicySetFinderModule(XACMLPolicy xpolicy)
   {
      PolicySetFinderModule psfm = new PolicySetFinderModule();
      //Check for enclosed policies
      List<AbstractPolicy> sunxacmlPolicies = new ArrayList<AbstractPolicy>();
      this.recursivePopulate(xpolicy, sunxacmlPolicies, psfm);

      psfm.set((PolicySet) xpolicy.get(XACMLConstants.UNDERLYING_POLICY), sunxacmlPolicies);

      //Make this PolicySetFinderModule the module for this policy set
      xpolicy.set(XACMLConstants.POLICY_FINDER_MODULE, psfm);
      return psfm;
   }
   
   private void recursivePopulate(XACMLPolicy policy, List<AbstractPolicy> policies, PolicySetFinderModule psfm)
   {
      List<XACMLPolicy> policyList = policy.getEnclosingPolicies();
      for (XACMLPolicy xp : policyList)
      {
         AbstractPolicy p = xp.get(XACMLConstants.UNDERLYING_POLICY);
         policies.add(p); 
         if (p instanceof PolicySet)
            this.recursivePopulate(xp, policies, psfm);
      }
   }
}
