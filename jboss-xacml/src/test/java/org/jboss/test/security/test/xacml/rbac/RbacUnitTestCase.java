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
package org.jboss.test.security.test.xacml.rbac;

import java.io.InputStream;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;
import org.junit.Test;
import static org.junit.Assert.assertNotNull;

import static org.junit.Assert.assertEquals; 

/**
 * @author Anil.Saldhana@redhat.com
 * @since Mar 29, 2011
 */
public class RbacUnitTestCase
{
   @Test
   public void testRbac() throws Exception
   { 
      validateCase(getResponse("rbac-request.xml"), 
            XACMLConstants.DECISION_PERMIT);
   }
   
   @Test
   public void testDenyRbac() throws Exception
   { 
      validateCase(getResponse("rbac-request-nopriv.xml"), 
            XACMLConstants.DECISION_NOT_APPLICABLE);
   }
   
   @Test
   public void testEmployeeCreatePurchaseOrderPermit() throws Exception
   { 
      validateCase(getResponse("rbac-employee-create.xml"), 
            XACMLConstants.DECISION_PERMIT);
   }
   
   @Test
   public void testEmployeeSignPurchaseOrderDeny() throws Exception
   { 
      validateCase(getResponse("rbac-employee-sign.xml"), 
            XACMLConstants.DECISION_NOT_APPLICABLE);
   }
   
   @Test
   public void testManagerCreatePurchaseOrderPermit() throws Exception
   { 
      validateCase(getResponse("rbac-manager-create.xml"), 
            XACMLConstants.DECISION_PERMIT);
   }
   
   @Test
   public void testManagerSignPurchaseOrderPermit() throws Exception
   { 
      validateCase(getResponse("rbac-manager-sign.xml"), 
            XACMLConstants.DECISION_PERMIT);
   }
   
   
   private PolicyDecisionPoint getPDP()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("locators/rbac/rbac-config.xml");
      assertNotNull("InputStream != null", is);

      return new JBossPDP(is);
   }
   
   private ResponseContext getResponse(String loc) throws Exception
   {
      loc = "test/requests/rbac/" + loc;
      return XACMLTestUtil.getResponse(getPDP(), loc);
   }
   
   private void validateCase(ResponseContext response, int decisionval) throws Exception
   {
      int decision = response.getDecision();
      
      switch(decisionval)
      {
         case XACMLConstants.DECISION_PERMIT: 
            assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
            break;
         case XACMLConstants.DECISION_DENY:
            assertEquals("DENY?", XACMLConstants.DECISION_DENY,decision);
            break;
         case XACMLConstants.DECISION_NOT_APPLICABLE:
               assertEquals("Not Applicable?", XACMLConstants.DECISION_NOT_APPLICABLE,decision);
               break;
         default: throw new RuntimeException("wrong value");
      }  
   } 
}