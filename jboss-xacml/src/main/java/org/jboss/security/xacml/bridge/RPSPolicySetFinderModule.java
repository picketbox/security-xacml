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
package org.jboss.security.xacml.bridge;

import java.util.ArrayList;
import java.util.List;

import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.MatchResult;
import org.jboss.security.xacml.sunxacml.PolicySet;
import org.jboss.security.xacml.sunxacml.ctx.Status;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;

/**
 * A Policy Set Finder Module that holds the RBAC Role Policy Sets
 * @author Anil.Saldhana@redhat.com
 * @since Mar 30, 2011
 */
public class RPSPolicySetFinderModule extends PolicySetFinderModule
{
   protected List<PolicySet> policySets = new ArrayList<PolicySet>();
   
   public void add(PolicySet ps)
   {
      policySets.add(ps);
   }

   @Override
   public PolicyFinderResult findPolicy(EvaluationCtx context)
   { 
      AbstractPolicy selectedPolicy = null;
   
      for( PolicySet policySet: policySets)
      {
         MatchResult match = policySet.match(context);
         int result = match.getResult();

         // if target matching was indeterminate, then return the error
         if (result == MatchResult.INDETERMINATE)
            return new PolicyFinderResult(match.getStatus());
      // see if the target matched
         if (result == MatchResult.MATCH)
         {
            // see if we previously found another match
            if (selectedPolicy != null)
            {
               // we found a match before, so this is an error
               ArrayList<String> code = new ArrayList<String>();
               code.add(Status.STATUS_PROCESSING_ERROR);
               Status status = new Status(code, "RPSPolicySetFinderModule::too many applicable " + "top-level policies");
               return new PolicyFinderResult(status);
            }

            // this is the first match we've found, so remember it
            selectedPolicy = policySet;
         }
      }
      // return the single applicable policy (if there was one)
      return new PolicyFinderResult(selectedPolicy);
   }  
}