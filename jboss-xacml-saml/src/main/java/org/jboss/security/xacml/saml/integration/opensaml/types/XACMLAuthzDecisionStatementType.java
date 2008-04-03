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
package org.jboss.security.xacml.saml.integration.opensaml.types;

import javax.xml.namespace.QName;

import org.jboss.security.xacml.interfaces.ElementMappingType;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.saml.integration.opensaml.constants.SAMLXACMLConstants;
import org.opensaml.saml2.core.Statement;
import org.w3c.dom.Document;


/**
 *  Represents a decision from XACML PDP
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public interface XACMLAuthzDecisionStatementType extends Statement, ElementMappingType
{
   /** Element local name. */
   String DEFAULT_ELEMENT_LOCAL_NAME = "XACMLAuthzDecisionStatement"; 

   /** Default element name for XACML 1.0. */
   QName DEFAULT_ELEMENT_NAME_XACML10 = new QName(SAMLXACMLConstants.SAML2_XACML10P_NS,
           DEFAULT_ELEMENT_LOCAL_NAME, SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** Default element name for XACML 1.1. */
   QName DEFAULT_ELEMENT_NAME_XACML11 = new QName(SAMLXACMLConstants.SAML2_XACML1_1P_NS,
           DEFAULT_ELEMENT_LOCAL_NAME, SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** Default element name for XACML 2.0. */
   QName DEFAULT_ELEMENT_NAME_XACML20 = new QName(SAMLXACMLConstants.SAMLP,
           DEFAULT_ELEMENT_LOCAL_NAME, SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);
   
   /** Local name of the XSI type. */
   public static final String TYPE_LOCAL_NAME = "XACMLAuthzDecisionStatementType";

   /** QName of the XSI type.XACML1.0. */
   QName TYPE_NAME_XACML10 = new QName(SAMLXACMLConstants.SAML2_XACML10P_NS, TYPE_LOCAL_NAME,
           SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** QName of the XSI type.XACML1.1. */
   QName TYPE_NAME_XACML11 = new QName(SAMLXACMLConstants.SAML2_XACML1_1P_NS, TYPE_LOCAL_NAME,
           SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** QName of the XSI type.XACML2.0. */
   QName TYPE_NAME_XACML20 = new QName(SAMLXACMLConstants.SAML2_XACML20P_NS, TYPE_LOCAL_NAME,
           SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   RequestContext getRequest();

   ResponseContext getResponse();

   void setRequest(RequestContext request);
 
   void setResponse(ResponseContext response); 
   
   void setOwnerDocument(Document doc);
   Document getOwnerDocument();
}