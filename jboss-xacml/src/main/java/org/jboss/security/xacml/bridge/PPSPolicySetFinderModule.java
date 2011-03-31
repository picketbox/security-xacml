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

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicyMetaData;
import org.jboss.security.xacml.sunxacml.PolicySet;
import org.jboss.security.xacml.sunxacml.VersionConstraints;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;

/**
 * A Policy Set Finder Module that holds the RBAC Permission Policy Sets
 * @author Anil.Saldhana@redhat.com
 * @since Mar 30, 2011
 */
public class PPSPolicySetFinderModule extends PolicySetFinderModule
{
   protected List<PolicySet> policySets = new ArrayList<PolicySet>();
   protected List<Policy> policies = new ArrayList<Policy>();
   
   public void add(PolicySet ps)
   {
      policySets.add(ps);
   }
   
   public void add(Policy p)
   {
      policies.add(p);
   }

   @Override
   public PolicyFinderResult findPolicy(EvaluationCtx context)
   { 
      return new PolicyFinderResult();
   }

   @Override
   public PolicyFinderResult findPolicy(URI idReference, int type, VersionConstraints constraints,
         PolicyMetaData parentMetaData)
   { 
      if( idReference != null )
      {
         for(PolicySet policySet: policySets)
         {
            if( policySet.getId().toString().equals(idReference.toString()))
            {
               return new PolicyFinderResult(policySet);
            }
         }
         for(Policy policy: policies)
         {
            if( policy.getId().toString().equals(idReference.toString()))
            {
               return new PolicyFinderResult(policy);
            }
         }
      }
      return new PolicyFinderResult();
   }
}