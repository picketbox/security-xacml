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

import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.jboss.security.xacml.util.JBossXACMLUtil;
import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 *  Marshaller for XACMLzDecisionStatementType
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class XACMLAuthzDecisionStatementTypeMarshaller extends AbstractSAMLObjectMarshaller
{ 
   @Override
   public Element marshall(XMLObject xmlObject, Element parentElement) 
   throws MarshallingException
   {
      XACMLAuthzDecisionStatementType xacmlType = (XACMLAuthzDecisionStatementType) xmlObject;
      
      Element xacmlDecisionElement = xacmlType.asElement(parentElement.getOwnerDocument());
      
      parentElement.appendChild(xacmlDecisionElement);
      
      ResponseContext responseContext = xacmlType.getResponse();
      if(responseContext != null)
      {
         Node responseRoot = responseContext.getDocumentElement();
         if(responseRoot != null)
         {
            XMLHelper.adoptElement((Element) responseRoot, parentElement.getOwnerDocument());  
            xacmlDecisionElement.appendChild(responseRoot);
         }
         else
         {
            try
            {
               Element elem = JBossXACMLUtil.getResponseContextElement(responseContext);
               XMLHelper.adoptElement(elem, parentElement.getOwnerDocument());  
               xacmlDecisionElement.appendChild(elem);
            }
            catch (Exception e)
            {
               throw new RuntimeException(e);
            }
         }
      } 
      
      RequestContext requestContext = xacmlType.getRequest();
      if(requestContext != null)
      {
         Node requestRoot = requestContext.getDocumentElement();
         if(requestRoot != null)
         { 
            XMLHelper.adoptElement((Element) requestRoot, parentElement.getOwnerDocument());  
            xacmlDecisionElement.appendChild(requestRoot);
         } 
      }
      
      return parentElement; 
   } 
}
