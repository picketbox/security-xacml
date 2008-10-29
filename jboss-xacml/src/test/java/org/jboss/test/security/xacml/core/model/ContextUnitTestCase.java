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
package org.jboss.test.security.xacml.core.model;

import java.io.InputStream;

import junit.framework.TestCase;

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
 *  Construction of request/response
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 20, 2007 
 *  @version $Revision$
 */
public class ContextUnitTestCase extends TestCase
{
   public void testConstructRequest() throws Exception
   {
      RequestType requestType = new RequestType();
      requestType.getSubject().add(createSubject());
      requestType.getResource().add(createResource());
      requestType.setAction(createAction());
      requestType.setEnvironment(new EnvironmentType());

      RequestContext requestCtx = RequestResponseContextFactory.createRequestCtx();
      requestCtx.setRequest(requestType);

      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("test/config/interopPolicySetConfig.xml");
      assertNotNull("InputStream != null", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      assertNotNull("JBossPDP is != null", pdp);

      assertEquals("Case 1 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp, requestCtx));
   }

   private SubjectType createSubject()
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
            "urn:xacml:2.0:interop:example:subject:buy-offer-price", "xacml20.interop.com", 100);
      subject.getAttribute().add(attBuyOfferShare);

      AttributeType attRequestExtCred = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:subject:req-credit-ext-approval", "xacml20.interop.com", "false");
      subject.getAttribute().add(attRequestExtCred);

      AttributeType attRequestTradeApproval = RequestAttributeFactory.createStringAttributeType(
            "urn:xacml:2.0:interop:example:subject:req-trade-approval", "xacml20.interop.com", "false");
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
