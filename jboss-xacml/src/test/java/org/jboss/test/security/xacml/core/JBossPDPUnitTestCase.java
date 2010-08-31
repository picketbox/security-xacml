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
import org.jboss.security.xacml.core.model.context.ActionType;
import org.jboss.security.xacml.core.model.context.AttributeType;
import org.jboss.security.xacml.core.model.context.EnvironmentType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResourceType;
import org.jboss.security.xacml.core.model.context.SubjectType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;


/**
 *  Unit tests for the JBossPDP
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossPDPUnitTestCase extends AbstractJBossXACMLInteropTestBase
{ 
   /**Enable to see the xacml request in system out for the objects case**/
   //Enable for request trace
   private boolean debug = "true".equals(System.getProperty("debug", "false"));
   
   
   public  String getConfigFileName()
   {
      return "test/config/interopPolicySetConfig.xml";
   }

   public void testInteropTestWithXMLRequests() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(getConfigFileName());
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

      validateInteropCases(pdp);
   }

   public void testInteropTestWithObjects() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(getConfigFileName());
      assertNotNull("InputStream != null", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      assertNotNull("JBossPDP is != null", pdp);

      assertEquals("Case 1 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            getRequestContext("false", "false", 10)));
      assertEquals("Case 2 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp,
            getRequestContext("false", "false", 1)));
      assertEquals("Case 3 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp,
            getRequestContext("true", "false", 5)));
      assertEquals("Case 4 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            getRequestContext("false", "false", 9)));
      assertEquals("Case 5 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            getRequestContext("true", "false", 10)));
      assertEquals("Case 6 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp,
            getRequestContext("true", "false", 15)));
      assertEquals("Case 7 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp,
            getRequestContext("true", "true", 10)));
   }

   private RequestContext getRequestContext(String reqTradeAppr, String reqCreditAppr, int buyPrice) throws Exception
   {
      RequestType request = new RequestType();
      request.getSubject().add(createSubject(reqTradeAppr, reqCreditAppr, buyPrice));
      request.getResource().add(createResource());
      request.setAction(createAction());
      request.setEnvironment(new EnvironmentType());

      RequestContext requestCtx = RequestResponseContextFactory.createRequestCtx();
      requestCtx.setRequest(request);
      if (debug)
         requestCtx.marshall(System.out);

      return requestCtx;
   }

   private SubjectType createSubject(String reqTradeAppr, String reqCreditAppr, int buyPrice)
   {
      //Create a subject type
      SubjectType subject = new SubjectType();
      subject.setSubjectCategory("urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
      //create the subject attributes
      AttributeType attSubjectID = RequestAttributeFactory.createStringAttributeType(
            "urn:oasis:names:tc:xacml:1.0:subject:subject-id", "xacml20.interop.com", "123456");
      subject.getAttribute().add(attSubjectID);

      AttributeType attUserName = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:subject:user-name", "xacml20.interop.com", "John Smith");
      subject.getAttribute().add(attUserName);

      AttributeType attBuyNumShares = RequestAttributeFactory.createIntegerAttributeType(
            "urn:xacml:2.0:interop:example:subject:buy-num-shares", "xacml20.interop.com", 1000);
      subject.getAttribute().add(attBuyNumShares);

      AttributeType attBuyOfferShare = RequestAttributeFactory.createIntegerAttributeType(
            "urn:xacml:2.0:interop:example:subject:buy-offer-price", "xacml20.interop.com", buyPrice);
      subject.getAttribute().add(attBuyOfferShare);

      AttributeType attRequestExtCred = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:subject:req-credit-ext-approval", "xacml20.interop.com", reqCreditAppr);
      subject.getAttribute().add(attRequestExtCred);

      AttributeType attRequestTradeApproval = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:subject:req-trade-approval", "xacml20.interop.com", reqTradeAppr);
      subject.getAttribute().add(attRequestTradeApproval);

      return subject;
   }

   public ResourceType createResource()
   {
      ResourceType resourceType = new ResourceType();

      AttributeType attResourceID = RequestAttributeFactory.createStringAttributeType(
            "urn:oasis:names:tc:xacml:1.0:resource:resource-id", "xacml20.interop.com", "CustomerAccount");
      resourceType.getAttribute().add(attResourceID);

      AttributeType attOwnerID = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:resource:owner-id", "xacml20.interop.com", "123456");
      resourceType.getAttribute().add(attOwnerID);

      AttributeType attOwnerName = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:resource:owner-name", "xacml20.interop.com", "John Smith");
      resourceType.getAttribute().add(attOwnerName);

      AttributeType attAccountStatus = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:resource:account-status", "xacml20.interop.com", "Active");
      resourceType.getAttribute().add(attAccountStatus);

      AttributeType attCreditLine = RequestAttributeFactory.createIntegerAttributeType(
            "urn:xacml:2.0:interop:example:resource:credit-line", "xacml20.interop.com", 15000);
      resourceType.getAttribute().add(attCreditLine);

      AttributeType attCurrentCredit = RequestAttributeFactory.createIntegerAttributeType(
            "urn:xacml:2.0:interop:example:resource:current-credit", "xacml20.interop.com", 10000);
      resourceType.getAttribute().add(attCurrentCredit);

      AttributeType attTradeLimit = RequestAttributeFactory.createIntegerAttributeType(
            "urn:xacml:2.0:interop:example:resource:trade-limit", "xacml20.interop.com", 10000);
      resourceType.getAttribute().add(attTradeLimit);
      return resourceType;
   }

   private ActionType createAction()
   {
      ActionType actionType = new ActionType();
      AttributeType attActionID = RequestAttributeFactory.createStringAttributeType(
            "urn:oasis:names:tc:xacml:1.0:action:action-id", "xacml20.interop.com", "Buy");
      actionType.getAttribute().add(attActionID);
      return actionType;
   }
}
