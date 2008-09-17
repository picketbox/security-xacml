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
import java.util.List;

import org.jboss.security.xacml.saml.integration.opensaml.core.OpenSAMLUtil;
import org.jboss.security.xacml.saml.integration.opensaml.util.DOMUtil;
import org.jboss.security.xacml.saml.integration.opensaml.util.SAML2Util;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
 
/**
 *  Represents a SAML Request
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class JBossSAMLRequest
{ 
   /**
    * Build a SAML Request
    * @param issueInstant
    * @param requestId Id for the request
    * @param issuerId ID of the issuer (can be null)
    * @return
    */
   public SAMLObject buildRequest(DateTime issueInstant, 
         String requestId, String issuerId)
   {
      if(issueInstant == null)
         issueInstant = new DateTime(ISOChronology.getInstanceUTC());
      
      RequestAbstractType samlRequest = 
         (RequestAbstractType) OpenSAMLUtil.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
      
      if(issuerId != null)
      {
         Issuer issuer = (Issuer) OpenSAMLUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
         issuer.setValue(issuerId);
         samlRequest.setIssuer(issuer);  
      }
      
      samlRequest.setID(requestId);
      samlRequest.setIssueInstant(issueInstant);
      
      //Hard code support for SAMl2
      samlRequest.setVersion(SAMLVersion.VERSION_20);
      
      return samlRequest; 
   }
   
   /**
    * Given a saml request file, parse the saml object
    * @param requestFile
    * @return
    * @throws Exception
    */
   public SAMLObject getSAMLRequest(String requestFile) throws Exception
   {
      Document document = DOMUtil.parse(new File(requestFile), true);
      return getSAMLObject(document);
   }
   
   /**
    * Parse the saml object from the input stream
    * @param requestStream
    * @return
    * @throws Exception
    */
   public SAMLObject getSAMLRequest(InputStream requestStream) 
   throws Exception
   {
      Document document = DOMUtil.parse(requestStream, true);
      return getSAMLObject(document);
   }
    
   private SAMLObject getSAMLObject(Document document) throws UnmarshallingException
   {
      if(document == null)
         throw new IllegalStateException("Document parsed is null");
      
      SAML2Util util = new SAML2Util();
      Element docElement = document.getDocumentElement();
      if(docElement == null)
         throw new IllegalStateException("Document Element is null");
      XMLObject xmlObject = util.toXMLObject(docElement);
      if(xmlObject instanceof Envelope)
      {
         Envelope envelope = (Envelope) xmlObject; 
         Body soapBody = envelope.getBody();
         List<XMLObject> children = soapBody.getOrderedChildren();
         if(children != null)
         {
            for(XMLObject child: children)
            {
               if(child instanceof SAMLObject)
               {
                  return (SAMLObject) child;
               }
            }
         }
      }
      else
      if(xmlObject instanceof SAMLObject)
      {
        return (SAMLObject) xmlObject;
      }
      throw new RuntimeException("Unknown Object:"+xmlObject.getClass().getCanonicalName()) ;
   }
}