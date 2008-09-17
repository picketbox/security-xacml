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
package org.jboss.security.xacml.saml.integration.opensaml.request;

import java.io.File;
import java.io.InputStream;

import org.jboss.security.xacml.saml.integration.opensaml.core.OpenSAMLUtil;
import org.jboss.security.xacml.saml.integration.opensaml.util.DOMUtil;
import org.jboss.security.xacml.saml.integration.opensaml.util.SAML2Util;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *  SAML Response
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class JBossSAMLResponse
{
   /**
    * Given a response file, parse the SAML Object
    * representing the response
    * @param responseFile
    * @return
    * @throws Exception
    */
   public SAMLObject getSAMLResponse(String responseFile) throws Exception
   {
      Document document = DOMUtil.parse(new File(responseFile), true);
      return getSAMLObject(document);
   }
   
   /**
    * Get the SAML Object
    * @param responseFile
    * @return
    * @throws Exception
    */
   public SAMLObject getSAMLResponse(InputStream responseFile) 
   throws Exception
   {
      Document document = DOMUtil.parse(responseFile, true);
      return getSAMLObject(document);
   }
   
   /**
    * Get a response object with the issue instant, response ID
    * and Issuer ID
    * <b>Note the response has been set to a status of success.</b>
    * 
    * @param issueInstant if null, get the current time
    * @param responseId The ID of the responses
    * @param issuerId Id of the Response Issuer - can be null
    * @return
    * @throws IllegalArgumentException if responseID is null
    */
   public Response getSAMLResponse(DateTime issueInstant, 
         String responseId, String issuerId)
   {
      if(responseId == null)
         throw new IllegalArgumentException("responseID is null");
      
      if(issueInstant == null)
         issueInstant = new DateTime(ISOChronology.getInstanceUTC());
      
      Response samlResponse = (Response) OpenSAMLUtil.buildXMLObject(Response.DEFAULT_ELEMENT_NAME); 
      samlResponse.setID(responseId);
      samlResponse.setIssueInstant(issueInstant);
      
      if(issuerId != null)
      {
         Issuer issuer = (Issuer) OpenSAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
         issuer.setValue(issuerId);
         samlResponse.setIssuer(issuer); 
      }
      
      //Set samlp:Status
      Status status = (Status) OpenSAMLUtil.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
      StatusCode statusCode = (StatusCode) OpenSAMLUtil.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
      statusCode.setValue(StatusCode.SUCCESS_URI);
      status.setStatusCode(statusCode);
      samlResponse.setStatus(status);
       
      return samlResponse;
   }
    
   private SAMLObject getSAMLObject(Document document) throws UnmarshallingException
   {
      if(document == null)
         throw new IllegalStateException("Document parsed is null");
      
      SAML2Util util = new SAML2Util();
      Element docElement = document.getDocumentElement();
      if(docElement == null)
         throw new IllegalStateException("Document Element is null");
      return (SAMLObject) util.toXMLObject(docElement);
   } 
}