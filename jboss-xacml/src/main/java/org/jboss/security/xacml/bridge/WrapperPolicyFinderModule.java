/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
  * by the @authors tag. See the copyright.txt in the distribution for a
  * full listing of individual contributors.
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

import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicyMetaData;
import org.jboss.security.xacml.sunxacml.VersionConstraints;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;
 
 

/**
 *  PolicyFinderModule that returns the enclosing Policy Object
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class WrapperPolicyFinderModule extends PolicyFinderModule
{ 
   protected PolicyFinder policyFinder = null;
   private Policy policy = null;;
   
   public WrapperPolicyFinderModule(Policy policy)
   {
      this.policy  = policy;
   }
   
   /**
    * @see PolicyFinderModule#init(com.sun.xacml.finder.PolicyFinder)
    */
   public void init(PolicyFinder policyFinder)
   {
      this.policyFinder = policyFinder;
   }
 
   /**
    * @see PolicyFinderModule#findPolicy(com.sun.xacml.EvaluationCtx)
    */
   public PolicyFinderResult findPolicy(EvaluationCtx evaluationCtx)
   {
      return new PolicyFinderResult(policy);
   }
 
   /**
    * @see PolicyFinderModule#findPolicy(java.net.URI, int, 
    *        com.sun.xacml.VersionConstraints, com.sun.xacml.PolicyMetaData)
    */
   public PolicyFinderResult findPolicy(URI arg0, int arg1, 
         VersionConstraints arg2, PolicyMetaData arg3)
   {
      return new PolicyFinderResult(policy);
   }
 
   /**
    * @see PolicyFinderModule#isRequestSupported()
    */
   public boolean isRequestSupported()
   {
      return true;
   }
   
}
