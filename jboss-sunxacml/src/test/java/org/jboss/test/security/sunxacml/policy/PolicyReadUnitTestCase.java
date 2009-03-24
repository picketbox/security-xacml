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
package org.jboss.test.security.sunxacml.policy;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.support.SimplePDP;

/**
 * Unit test for reading Policies for the Sunxacml PDP
 * @author Anil.Saldhana@redhat.com
 * @since Mar 21, 2009
 */
public class PolicyReadUnitTestCase extends TestCase
{ 
   /**
    * SECURITY-394: bag-size throws IllegalArgumentException in FunctionBase
    * @throws Exception
    */
   public void testBagSize() throws Exception 
   {
      String fileName = "src/test/resources/policies/bag-size/bag-size-policy.xml";
      readPolicyIntoPDP(fileName);
   }
   
   
   public void testFunctionMatch_01() throws Exception
   {   
      String fileName = "src/test/resources/policies/function-match/function-match-policy-01.xml";
      readPolicyIntoPDP(fileName);
   }
   
   public void testFunctionMatch_02() throws Exception
   {   
      String fileName = "src/test/resources/policies/function-match/function-match-policy-02.xml";
      readPolicyIntoPDP(fileName);
   }
   
   public void testHimmss09_01() throws Exception
   {
      String fileName = "src/test/resources/policies/himss09/himss-policy-01.xml";
      readPolicyIntoPDP(fileName); 
   }
   
   private void readPolicyIntoPDP(String fileName) throws Exception
   {
      String[] policies = new String[] {fileName};
      SimplePDP pdp = new SimplePDP(policies);
      assertNotNull(pdp); 
   }
}