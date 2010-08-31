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
package org.jboss.test.security.xacml.core;

import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;

import junit.framework.TestCase;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Aug 30, 2010
 */
public class AbstractJBossXACMLInteropTestBase extends TestCase
{
   /**
    * Validate the 7 Oasis XACML Interoperability Use Cases
    * @param pdp
    * @throws Exception
    */
   public static void validateInteropCases(PolicyDecisionPoint pdp) throws Exception
   {
      TestCase.assertNotNull("JBossPDP is != null", pdp);
      TestCase.assertEquals("Case 1 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase1-request.xml"));
      TestCase.assertEquals("Case 2 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase2-request.xml"));
      TestCase.assertEquals("Case 3 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase3-request.xml"));
      TestCase.assertEquals("Case 4 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase4-request.xml"));
      TestCase.assertEquals("Case 5 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase5-request.xml"));
      TestCase.assertEquals("Case 6 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase6-request.xml"));
      TestCase.assertEquals("Case 7 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp,
            "test/requests/interop/scenario2-testcase7-request.xml"));
   }

}