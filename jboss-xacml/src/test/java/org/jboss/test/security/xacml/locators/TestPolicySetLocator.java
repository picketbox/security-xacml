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
package org.jboss.test.security.xacml.locators;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jboss.security.xacml.bridge.JBossPolicyFinder;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.locators.JBossPolicySetLocator;

/**
 * Test Policy Set Locator for the Interop test case(JustLocatorUnitTestCase)
 * @author Anil.Saldhana@redhat.com
 * @since Apr 8, 2009
 */
@org.junit.Ignore
public class TestPolicySetLocator extends JBossPolicySetLocator
{
   public TestPolicySetLocator()
   {
      
   }

   @Override
   public <T> void set(String key, T obj)
   {
      if(XACMLConstants.POLICY_FINDER.equals(key))
      {
         JBossPolicyFinder jbf = (JBossPolicyFinder) obj;
         String policySetLocation = "test/policies/interop/xacml-policySet.xml";
         String[] arr = new String[] { 
               "test/policies/interop/xacml-policy2.xml",
               "test/policies/interop/xacml-policy3.xml",
               "test/policies/interop/xacml-policy4.xml",
               "test/policies/interop/xacml-policy5.xml"}; 
         ClassLoader tcl = Thread.currentThread().getContextClassLoader();
         
         XACMLPolicy policySet = null;
         try
         {
            policySet = PolicyFactory.createPolicySet(tcl.getResourceAsStream(policySetLocation),jbf);
         }
         catch (Exception e1)
         {
            throw new RuntimeException(e1);
         }
         
         List<XACMLPolicy> policyList = new ArrayList<XACMLPolicy>();
         for (String str:arr)
         {
            InputStream is = tcl.getResourceAsStream(str);
            if(is == null)
               throw new IllegalStateException("Inputstream is null");
            
            try
            {
               policyList.add(PolicyFactory.createPolicy(is));
            }
            catch (Exception e)
            {
              throw new RuntimeException(e);
            }
         }  
         
         policySet.setEnclosingPolicies(policyList); 
         
         Set<XACMLPolicy> set = new HashSet<XACMLPolicy>();
         set.add(policySet);
         this.setPolicies(set);                 
      }
      super.set(key, obj);
   } 
}