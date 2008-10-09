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
package org.jboss.security.xacml.saml.integration.opensaml.impl;

import java.io.IOException;

import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.opensaml.saml2.core.impl.RequestAbstractTypeUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Element;


/**
 *  Unmarshaller
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 28, 2008 
 *  @version $Revision$
 */
public class XACMLAuthzDecisionQueryTypeUnMarshaller 
extends RequestAbstractTypeUnmarshaller
{
   /** Constructor. */
   public XACMLAuthzDecisionQueryTypeUnMarshaller() 
   {
       super();
   }
  
   /** {@inheritDoc} */
   protected void processChildElement(XMLObject parentObject, 
         XMLObject childObject) throws UnmarshallingException 
   {
       XACMLAuthzDecisionQueryType xacmlauthzdecisionquery = (XACMLAuthzDecisionQueryType) parentObject;

       if (childObject instanceof RequestContext) {
           xacmlauthzdecisionquery.setRequest((RequestContext) childObject);
       } else {
           super.processChildElement(parentObject, childObject);
       }
   } 

   @Override
   protected void unmarshallChildElement(XMLObject xmlObject, Element childElement) throws UnmarshallingException
   {
      XACMLAuthzDecisionQueryType xacmlAuthzDecisionQueryType = null;
      if(xmlObject instanceof XACMLAuthzDecisionQueryType)
      {
         xacmlAuthzDecisionQueryType = (XACMLAuthzDecisionQueryType) xmlObject;
      }
      if(childElement.getLocalName().equals("Request") 
            && childElement.getNamespaceURI().equals(XACMLConstants.CONTEXT_SCHEMA))
      {
         //process the xacml request
         RequestContext requestContext = RequestResponseContextFactory.createRequestCtx();
         try
         {
            requestContext.readRequest(childElement);
         }
         catch (IOException e)
         {
            throw new RuntimeException(e);
         } 
         xacmlAuthzDecisionQueryType.setRequest(requestContext);
      } 
      else
      super.unmarshallChildElement(xmlObject, childElement);
   } 
}
