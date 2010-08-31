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
package org.jboss.test.security.sunxacml.conformance.support;

import java.net.URI;
import java.util.ArrayList;

import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.PolicyMetaData;
import org.jboss.security.xacml.sunxacml.PolicyReference;
import org.jboss.security.xacml.sunxacml.VersionConstraints;
import org.jboss.security.xacml.sunxacml.ctx.Status;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;

/**
 * Override the findPolicy method
 * @author Anil.Saldhana@redhat.com
 * @since Mar 25, 2009
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class ConformanceTestPolicyFinderModule extends TestPolicyFinderModule
{
   @Override
   public PolicyFinderResult findPolicy(URI idReference, int type, VersionConstraints constraints,
         PolicyMetaData metaData)
   {
      String fileName = null;
      
      // based on the type, see if we have any references available, and
      // if we do then get the filename
      if (type == PolicyReference.POLICY_REFERENCE) {
          if (policyRefs == null)
              return new PolicyFinderResult();

          fileName = (String)(policyRefs.get(idReference.toString()));
      } else {
          if (policySetRefs == null)
              return new PolicyFinderResult();

          fileName = (String)(policySetRefs.get(idReference.toString()));
      }

      // if we had no mapping available, return with no referenced policy
      if (fileName == null)
          return new PolicyFinderResult();

      // load the referenced policy
      AbstractPolicy policy = loadPolicy(fileName, finder);

      // if there was an error loading the policy, return the error
      if (policy == null) {
          ArrayList code = new ArrayList();
          code.add(Status.STATUS_PROCESSING_ERROR);
          Status status = new Status(code,
                                     "couldn't load referenced policy");
          return new PolicyFinderResult(status);
      }
      
      // return the referenced policy
      return new PolicyFinderResult(policy);
   } 
}
