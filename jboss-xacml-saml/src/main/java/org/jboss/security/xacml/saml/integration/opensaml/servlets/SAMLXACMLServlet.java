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
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.saml.integration.opensaml.core.JBossXACMLSAMLConfiguration;
import org.jboss.security.xacml.saml.integration.opensaml.core.OpenSAMLUtil;
import org.jboss.security.xacml.saml.integration.opensaml.request.JBossSAMLRequest;
import org.jboss.security.xacml.saml.integration.opensaml.request.JBossSAMLResponse;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.jboss.security.xacml.saml.integration.opensaml.util.SAML2Util;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
 

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
   
   private String policyConfigFileName = "policyConfig.xml";
   
   private boolean debug = false;

   static
   {
      try
      {
         JBossXACMLSAMLConfiguration.initialize();
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }   
   }
   
   public void init() throws ServletException
   {    
      responseId = getServletContext().getInitParameter("responseID");
      if(responseId == null)
         responseId = "response-id:1";
      
      issuerId = getServletContext().getInitParameter("issuerID");
      if(issuerId == null)
         issuerId = "issue-id:1";
      
      policyConfigFileName = getServletContext().getInitParameter("policyConfigFileName");
      if(policyConfigFileName == null)
         policyConfigFileName = "policyConfig.xml";
      
      String debugStr = getServletContext().getInitParameter("debug");
      if("TRUE".equalsIgnoreCase(debugStr))
         debug = true;
      
      super.init();     
   }


   @Override
   protected void doPost(HttpServletRequest request, HttpServletResponse response) 
   throws ServletException, IOException
   {
      SAML2Util util = new SAML2Util();
      JBossSAMLRequest samlRequest = new JBossSAMLRequest();
      PrintWriter pw = null;
      try
      {
         SAMLObject samlObject = samlRequest.getSAMLRequest(request.getInputStream());
         if(debug)
           logXMLObject(samlObject);
         
         XACMLAuthzDecisionQueryType xacmlRequest = (XACMLAuthzDecisionQueryType)samlObject;
         
         RequestContext requestContext = xacmlRequest.getRequest();
         if(requestContext == null)
            throw new IllegalStateException("XACML Request Context is null");
         ResponseContext responseContext = getPDP().evaluate(requestContext);
    
         DateTime issueInstant = util.getIssueInstant();
           
         //We need to create a response to send back
         Response samlResponse = (new JBossSAMLResponse()).getSAMLResponse(issueInstant, 
                                                  responseId, issuerId);
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
         if(debug)
            logXMLObject(samlResponse);
         
         MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
         Marshaller samlResponseMarshaller = marshallerFactory.getMarshaller(samlResponse);
          
         response.setContentType("text/xml;charset=utf-8");;
         OutputStream os = response.getOutputStream();
         OutputStreamWriter osw = new OutputStreamWriter(os , "UTF-8");
         pw = new PrintWriter(osw);
         
         String resp = XMLHelper.nodeToString(samlResponseMarshaller.marshall(samlResponse));
         log(resp);
         pw.print(resp);  
         pw.flush();
      }
      catch (Exception e)
      {
         throw new ServletException(e); 
      } 
      finally
      {
         if(pw != null)
            pw.close();
      }
   }  
   
   private Element logXMLObject(XMLObject xmlObject)
   {
      MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
      Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
      Element elem = null;
      try
      {
         elem = marshaller.marshall(xmlObject);
         log(XMLHelper.prettyPrintXML(elem));
      }
      catch (MarshallingException e)
      {
         log(e.getLocalizedMessage(),e);
      }     
      return elem;
   }
   
   private PolicyDecisionPoint getPDP() throws PrivilegedActionException
   {
      ClassLoader tcl = AccessController.doPrivileged(new PrivilegedExceptionAction<ClassLoader>()
      {
         public ClassLoader run() throws Exception
         {
             return Thread.currentThread().getContextClassLoader();
         }
      });
      InputStream is = tcl.getResourceAsStream(this.policyConfigFileName);
      if(is == null)
         throw new IllegalStateException(policyConfigFileName  + " could not be located");
      return new JBossPDP(is); 
   }
}