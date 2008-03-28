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
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.opensaml.saml2.core.impl.RequestAbstractTypeImpl;
import org.opensaml.xml.schema.XSBooleanValue;


/**
 *  Implementation of the xacml authz decision query
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class XACMLAuthzDecisionQueryTypeImpl extends RequestAbstractTypeImpl
implements XACMLAuthzDecisionQueryType
{
   private RequestContext requestType;
   private XSBooleanValue combinePolicies;
   
   /* 
    * Constructor.
    * @param nsURI the namespace the element is in
    * @param localname the local name of the XML element 
    * @param prefix the prefix for the given namespace
    */
  protected XACMLAuthzDecisionQueryTypeImpl(String nsURI, String localname, 
        String prefix) 
  {
      super(nsURI, localname, prefix);
      setElementNamespacePrefix(prefix);
  }

   public XSBooleanValue getCombinePolicies()
   { 
      return combinePolicies;
   }

   public RequestContext getRequest()
   {   
      return requestType;
   }

   public boolean isCombinePolicies()
   { 
      return combinePolicies != null ? combinePolicies.getValue() : null;
   }

   public void setCombinePolicies(XSBooleanValue combinePolicies)
   {
     this.combinePolicies = combinePolicies;
   }

   public void setRequest(RequestContext request)
   {
      this.requestType = request;
   }  
}
