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
package org.jboss.security.xacml.saml.integration.opensaml.servlets;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.saml.integration.opensaml.core.OpenSAMLUtil;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeImplBuilder;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeUnMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionStatementTypeImplBuilder;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionStatementTypeMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionStatementTypeUnMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.request.JBossSAMLRequest;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
 

/**
 *  Servlet that reads in SAML Requests and
 *  then calls the PDP. Once a response comes
 *  from the PDP, it then creates a SAML Object 
 *  and sends it back
 *  
 *  You need to provide a policyConfig.xml that
 *  lists the locations of the policy files in the
 *  classpath
 *  
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class SAMLXACMLServlet extends HttpServlet
{
   private static final long serialVersionUID = 1L; 
   
   private String responseId =  null;
   
   private String issuerId = null;
   
   public void init() throws ServletException
   {
      try
      {
         org.opensaml.DefaultBootstrap.bootstrap();
         Configuration.registerObjectProvider(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20, 
               new XACMLAuthzDecisionQueryTypeImplBuilder(), 
               new XACMLAuthzDecisionQueryTypeMarshaller(), 
               new XACMLAuthzDecisionQueryTypeUnMarshaller(), 
               null);
         Configuration.registerObjectProvider(XACMLAuthzDecisionStatementType.DEFAULT_ELEMENT_NAME_XACML20, 
               new XACMLAuthzDecisionStatementTypeImplBuilder(), 
               new XACMLAuthzDecisionStatementTypeMarshaller(), 
               new XACMLAuthzDecisionStatementTypeUnMarshaller(), 
               null);
      }
      catch (ConfigurationException e)
      {
         throw new ServletException(e);
      }
      responseId = getServletContext().getInitParameter("responseID");
      if(responseId == null)
         responseId = "response-id:1";
      if(issuerId == null)
         issuerId = "issue-id:1";
      super.init();     
   }


   @Override
   protected void doPost(HttpServletRequest request, HttpServletResponse response) 
   throws ServletException, IOException
   {
      JBossSAMLRequest samlRequest = new JBossSAMLRequest();
      try
      {
         SAMLObject samlObject = samlRequest.getSAMLRequest(request.getInputStream());
         logXMLObject(samlObject);
         
         XACMLAuthzDecisionQueryType xacmlRequest = (XACMLAuthzDecisionQueryType)samlObject;
         RequestContext requestType = xacmlRequest.getRequest();
         if(requestType == null)
            throw new RuntimeException("xacml request is null"); 
         
         RequestContext requestContext = xacmlRequest.getRequest();
         if(requestContext == null)
            throw new IllegalStateException("XACML Request Context is null");
         ResponseContext responseContext = getPDP().evaluate(requestContext);
    
         DateTime issueInstant = getIssueInstant();
           
         //We need to create a response to send back
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
         logXMLObject(samlResponse);
      }
      catch (Exception e)
      {
         throw new ServletException(e); 
      } 
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
   
   public static DateTime getIssueInstant()
   {
      return new DateTime(ISOChronology.getInstanceUTC());
   }
   
   private void logXMLObject(XMLObject xmlObject)
   {
      MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
      Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
      try
      {
         log(XMLHelper.prettyPrintXML(marshaller.marshall(xmlObject)));
      }
      catch (MarshallingException e)
      {
         log(e.getLocalizedMessage());
      }     
   }
   
   private PolicyDecisionPoint getPDP()
   {
      InputStream is = getServletContext().getResourceAsStream("policyConfig.xml");
      return new JBossPDP(is); 
   }
}