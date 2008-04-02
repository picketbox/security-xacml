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

import java.util.List;

import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;


/**
 *  Implementation of the xacml authz decision statement
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class XACMLAuthzDecisionStatementTypeImpl extends AbstractSAMLObject 
implements XACMLAuthzDecisionStatementType
{
   private RequestContext requestContext;
   private ResponseContext responseContext; 

   /* 
    * Constructor.
    * @param nsURI the namespace the element is in
    * @param localname the local name of the XML element 
    * @param prefix the prefix for the given namespace
    */
   protected XACMLAuthzDecisionStatementTypeImpl(String nsURI, String localname, 
         String prefix) 
   {
      super(nsURI, localname, prefix);
      setElementNamespacePrefix(prefix);
   }

   public ResponseContext getResponse()
   {   
      return responseContext;
   }

   public void setResponse(ResponseContext response)
   {
      this.responseContext = response;
   }  

   public RequestContext getRequest()
   {   
      return requestContext;
   }

   public void setRequest(RequestContext request)
   {
      this.requestContext = request;
   }  
   
   /** {@inheritDoc} */
   public List<XMLObject> getOrderedChildren() 
   {
      throw new RuntimeException("Not implemented:getOrderedChildren()"); 
   }
}
