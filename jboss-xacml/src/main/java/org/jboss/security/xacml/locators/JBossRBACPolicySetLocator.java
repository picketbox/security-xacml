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

import java.util.List;
import java.util.Set;

import org.jboss.security.xacml.bridge.PPSPolicySetFinderModule;
import org.jboss.security.xacml.bridge.RPSPolicySetFinderModule;
import org.jboss.security.xacml.bridge.WrapperPolicyFinderModule;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicySet;

/**
 * A Policy Set Locator that follows the XACML RBAC Profile
 * @author Anil.Saldhana@redhat.com
 * @since Mar 29, 2011
 */
public class JBossRBACPolicySetLocator extends JBossPolicySetLocator
{
   public static final String ROLE_NS = "urn:oasis:names:tc:xacml:2.0:subject:role";
   public static final String RPS = "RPS";
   public static final String PPS = "PPS";
   
   protected RPSPolicySetFinderModule rpsFinderModule = new RPSPolicySetFinderModule();
   protected PPSPolicySetFinderModule ppsFinderModule = new PPSPolicySetFinderModule();

   @Override
   public void setPolicies(Set<XACMLPolicy> policies)
   {
      this.policies = policies;
      pfml.add(rpsFinderModule);
      pfml.add(ppsFinderModule);
      
      for (XACMLPolicy xp : policies)
      {
         if (xp.getType() == XACMLPolicy.POLICYSET)
         {
            handlePolicy(xp); 
         }
         else if (xp.getType() == XACMLPolicy.POLICY)
         {
            Policy p = xp.get(XACMLConstants.UNDERLYING_POLICY);
            WrapperPolicyFinderModule wpfm = new WrapperPolicyFinderModule(p);
            pfml.add(wpfm);
         }
      }
      this.map.put(XACMLConstants.POLICY_FINDER_MODULE, pfml);
   }
   
   protected void handlePolicy(XACMLPolicy xacmlPolicy)
   {
      List<XACMLPolicy> policyList = xacmlPolicy.getEnclosingPolicies();
      for (XACMLPolicy xp : policyList)
      {
         handlePolicy(xp); 
      }
      if(policyList.size() == 0)
      {
         AbstractPolicy aPolicy = xacmlPolicy.get(XACMLConstants.UNDERLYING_POLICY);
         if( aPolicy instanceof PolicySet)
         { 
            PolicySet policySet = (PolicySet) aPolicy;
            if( policySet.getId().toASCIIString().contains(RPS))
            {
               //This is RPS 
               rpsFinderModule.add(policySet);
            }
            else if( policySet.getId().toASCIIString().contains(PPS))
            {
               //This is PPS 
               ppsFinderModule.add(policySet);
            } 
         }  
      }
      
   }
}