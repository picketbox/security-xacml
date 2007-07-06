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
package org.jboss.test.security.xacml.core;

import java.io.InputStream;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;

import junit.framework.TestCase;

//$Id$

/**
 *  Unit tests for the JBossPDP
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossPDPUnitTestCase extends TestCase
{ 
   public void testInteropTest() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("test/config/interopPolicySetConfig.xml");
      assertNotNull("InputStream != null", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      assertNotNull("JBossPDP is != null", pdp);
//http://www.oasis-open.org/committees/download.php/24475/xacml-2.0-core-interop-draft-12-04.doc
/*
 Test (Trade-limit)(Cred-line)(Curr-cred)(Req-tr-appr) (Req-cr-appr) (Num-shrs)(Buy-price)(Expected Decision
 1     10000   15000           10000       False        False         1000       10  Deny
 2     10000   15000           10000       False        False         1000       1    Permit
 3     10000   15000           10000       True         False         1000       5   Permit
 4     10000   15000           10000       True         False         1000       9   Deny
 5     10000   15000           10000       True         False         1000       10  Deny
 6     10000   15000           10000       True         False         1000       15  Deny
 7     10000   15000           10000       True         True          1000       10  Permit
*/

      assertEquals("Case 1 should be deny", XACMLConstants.DECISION_DENY,
            getDecision(pdp,"test/requests/interop/scenario2-testcase1-request.xml"));
      assertEquals("Case 2 should be deny", XACMLConstants.DECISION_PERMIT,
            getDecision(pdp,"test/requests/interop/scenario2-testcase2-request.xml"));
      assertEquals("Case 3 should be deny", XACMLConstants.DECISION_PERMIT,
            getDecision(pdp,"test/requests/interop/scenario2-testcase3-request.xml"));
      assertEquals("Case 4 should be deny", XACMLConstants.DECISION_DENY,
            getDecision(pdp,"test/requests/interop/scenario2-testcase4-request.xml"));
      assertEquals("Case 5 should be deny", XACMLConstants.DECISION_DENY,
            getDecision(pdp,"test/requests/interop/scenario2-testcase5-request.xml"));
      assertEquals("Case 6 should be deny", XACMLConstants.DECISION_DENY,
            getDecision(pdp,"test/requests/interop/scenario2-testcase6-request.xml"));
      assertEquals("Case 7 should be deny", XACMLConstants.DECISION_PERMIT,
            getDecision(pdp,"test/requests/interop/scenario2-testcase7-request.xml"));
   } 
   
   private int getDecision(PolicyDecisionPoint pdp, String loc) throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(loc);
      RequestContext request = RequestResponseContextFactory.createRequestCtx();
      request.readRequest(is);
      ResponseContext response = pdp.evaluate(request);
      assertNotNull("Response is not null", response);
      return response.getDecision(); 
   }
}
