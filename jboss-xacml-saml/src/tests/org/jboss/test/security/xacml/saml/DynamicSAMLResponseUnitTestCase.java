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
package org.jboss.test.security.xacml.saml;

import junit.framework.TestCase;

import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.saml.integration.opensaml.core.JBossXACMLSAMLConfiguration;
import org.jboss.security.xacml.saml.integration.opensaml.core.OpenSAMLUtil;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AssertionImpl;

/**
 *  Construct SAML Response and test
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class DynamicSAMLResponseUnitTestCase extends TestCase
{

   protected void setUp() throws Exception
   {
      JBossXACMLSAMLConfiguration.initialize(); 
   }
   
   public void testSAMLResponse() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
      requestContext.readRequest(tcl.getResourceAsStream("xacml/xacmlrequest.xml"));
      
      ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
      responseContext.readResponse(tcl.getResourceAsStream("xacml/xacmlresponse.xml"));
      
      
      String responseId = "response-1";
      String issuerId = "issuer-1";
      
      DateTime issueInstant = new DateTime(ISOChronology.getInstanceUTC());
      Response samlResponse = getSAMLResponse(issueInstant, responseId, issuerId);
      
      //Create samlp:Assertion
      Assertion assertion = (Assertion) OpenSAMLUtil.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
      assertion.setID(responseId);
      assertion.setIssueInstant(issueInstant);
      
      Issuer issuer = (Issuer) OpenSAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
      issuer.setValue(issuerId);
      assertion.setIssuer(issuer);
      
      XACMLAuthzDecisionStatementType decision = (XACMLAuthzDecisionStatementType) 
         OpenSAMLUtil.buildXMLObject(XACMLAuthzDecisionStatementType.DEFAULT_ELEMENT_NAME_XACML20);

      decision.setResponse(responseContext);
      decision.setRequest(requestContext);
      
      //Some mismatch in the Statements for XACML
      AssertionImpl assertionImpl = (AssertionImpl) assertion;
      assertionImpl.getStatements().add(decision);
      
      samlResponse.getAssertions().add(assertionImpl);                   
   }
   
   private Response getSAMLResponse(DateTime issueInstant, String responseId,
         String issuerId)
   {   
      Response samlResponse = (Response) OpenSAMLUtil.buildXMLObject(Response.DEFAULT_ELEMENT_NAME); 
      samlResponse.setID(responseId);
      samlResponse.setIssueInstant(issueInstant);
      
      //Set samlp:Status
      Status status = (Status) OpenSAMLUtil.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
      StatusCode statusCode = (StatusCode) OpenSAMLUtil.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
      statusCode.setValue(StatusCode.SUCCESS_URI);
      status.setStatusCode(statusCode);
      samlResponse.setStatus(status);
       
      return samlResponse;
   }
}
