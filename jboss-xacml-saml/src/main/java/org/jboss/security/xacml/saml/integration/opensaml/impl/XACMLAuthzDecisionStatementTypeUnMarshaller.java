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
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Element;

/**
 *  
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class XACMLAuthzDecisionStatementTypeUnMarshaller 
extends AbstractSAMLObjectUnmarshaller
{

   @Override
   protected void processChildElement(XMLObject parentObject, 
         XMLObject childObject)
         throws UnmarshallingException
   {
      XACMLAuthzDecisionStatementType xacmlAuthzDecisionStatementType = 
         (XACMLAuthzDecisionStatementType) parentObject;

      if (childObject instanceof ResponseContext) 
      {
         xacmlAuthzDecisionStatementType.setResponse((ResponseContext) childObject);
      }
      else
      if (childObject instanceof RequestContext) 
      {
        xacmlAuthzDecisionStatementType.setRequest((RequestContext) childObject);
      }
      else 
      {
          super.processChildElement(parentObject, childObject);
      }
   } 

   @Override
   protected void unmarshallChildElement(XMLObject xmlObject, 
         Element childElement) throws UnmarshallingException
   {
      XACMLAuthzDecisionStatementType xacmlAuthzDecisionStatementType = null;
      if(xmlObject instanceof XACMLAuthzDecisionStatementType)
      {
         xacmlAuthzDecisionStatementType = (XACMLAuthzDecisionStatementType) xmlObject;
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
         xacmlAuthzDecisionStatementType.setRequest(requestContext);
      } 
      else
         if(childElement.getLocalName().equals("Response") 
               && childElement.getNamespaceURI().equals(XACMLConstants.CONTEXT_SCHEMA))
         {
            //process the xacml response
            ResponseContext responseContext = RequestResponseContextFactory.createResponseContext();
            try
            {
               responseContext.readResponse(childElement);
            }
            catch (IOException e)
            {
               throw new RuntimeException(e);
            } 
            xacmlAuthzDecisionStatementType.setResponse(responseContext);
         }
      else
      super.unmarshallChildElement(xmlObject, childElement);
   } 
}