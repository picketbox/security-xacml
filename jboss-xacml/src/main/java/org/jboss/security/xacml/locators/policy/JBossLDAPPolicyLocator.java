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
package org.jboss.security.xacml.locators.policy;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

import org.jboss.security.xacml.bridge.PolicySetFinderModule;
import org.jboss.security.xacml.bridge.WrapperPolicyFinderModule;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.locators.AbstractJBossPolicyLocator;
import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicySet;
import org.jboss.security.xacml.util.LDAPCommon;

/**
 * 
 * A PolicyLocator that searches for XACML policies and policy sets stored in an attribute of LDAP entries
 * The attribute contains the XACML policy as if the xml would be converted to a String.
 * This PolicyLocator is configured with the following options:
 * 
 * url - The LDAP server URL to connect to
 * factory - The JNDI factory that is JDK specific such as "com.sun.jndi.ldap.LdapCtxFactory"
 * username - The username to connect to the LDAP server. This user must have search privileges
 * password - The password of the user to connect to the LDAP server
 * filter - The search filter to be used to find the entries that have a policy
 * attribute - The name of the entry's attribute containing the XACML policy in the xml format
 * searchScope - Scope of the search for entries. Default is SUBTREE
 * searchTimeLimit - Search time limit. Default is 10000 (10 seconds)
 * 
 * The password value can be masked using PBE. To create a masked password invoke
 * org.jboss.security.xacml.util.PBEUtils salt iterationCount password
 * When using a masked password add also the options
 * salt - the 8 character String
 * iterationCount - an integer
 * Those options must have the same value used for encryption.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @author Anil.Saldhana@redhat.com
 * @version $Revision: 1 $
 */
public class JBossLDAPPolicyLocator extends AbstractJBossPolicyLocator
{  
   protected static Logger log = Logger.getLogger(JBossLDAPPolicyLocator.class.getName());
   
   // Common Utility class that is common for ldap integration
   protected LDAPCommon ldapCommon = new LDAPCommon();

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
      ldapCommon.processOptions(theoptions);
      
      init();
   }

   protected void init()
   {   
      ldapCommon.validateConfiguration( LDAPCommon.TYPE.POLICY );

      search();
   }

   protected void search() 
   { 
      NamingEnumeration<SearchResult> results = null;

      try
      {

         ldapCommon.constructJNDIContext();
         results = ldapCommon.search( null ); 
         while (results.hasMore())
         {
            SearchResult rs = results.next();
            Attributes attributes = rs.getAttributes();
            if (attributes != null)
            {
               Attribute xml = attributes.get( ldapCommon.getLdapAttribute() );
               if (xml != null)
               {
                  String xmlString = (String) xml.get();
                  try
                  {
                     byte[] xmlStream = xmlString.getBytes("UTF-8");
                     XACMLPolicy policy = PolicyFactory.createPolicy( new ByteArrayInputStream( xmlStream ));
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
         if( results != null )
         {
            try
            {
               results.close();
            }
            catch ( NamingException ignore )
            { 
            }
         }

         try
         {
            ldapCommon.closeJNDIContext();
         }
         catch (NamingException ignore )
         { 
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
