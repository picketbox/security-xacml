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

import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.saml.integration.opensaml.constants.SAMLXACMLConstants;
import org.jboss.security.xacml.saml.integration.opensaml.core.XACMLObject;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.schema.XSBooleanValue;
 
/**
 *  Represents a type for XACML authorization query request
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public interface XACMLAuthzDecisionQueryType extends RequestAbstractType, XACMLObject
{ 
   /** Element local name. */
   public static final String DEFAULT_ELEMENT_LOCAL_NAME = "XACMLAuthzDecisionQuery";

   /** Default element name for XACML 1.0. */
   public static final QName DEFAULT_ELEMENT_NAME_XACML10 = new QName(SAMLXACMLConstants.SAML2_XACML10P_NS,
           DEFAULT_ELEMENT_LOCAL_NAME, SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** Default element name for XACML 1.1. */
   public static final QName DEFAULT_ELEMENT_NAME_XACML11 = new QName(SAMLXACMLConstants.SAML2_XACML1_1P_NS,
           DEFAULT_ELEMENT_LOCAL_NAME, SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** Default element name for XACML 2.0. */
   public static final QName DEFAULT_ELEMENT_NAME_XACML20 = new QName(SAMLXACMLConstants.SAMLP,
           DEFAULT_ELEMENT_LOCAL_NAME, SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);
 
   /** Local name of the XSI type. */
   public static final String TYPE_LOCAL_NAME = "XACMLAuthzDecisionQueryType";

   /** QName of the XSI type.XACML1.0. */
   public static final QName TYPE_NAME_XACML10 = new QName(SAMLXACMLConstants.SAML2_XACML10P_NS, TYPE_LOCAL_NAME,
           SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** QName of the XSI type.XACML1.1. */
   public static final QName TYPE_NAME_XACML11 = new QName(SAMLXACMLConstants.SAML2_XACML1_1P_NS, TYPE_LOCAL_NAME,
           SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);

   /** QName of the XSI type.XACML2.0. */
   public static final QName TYPE_NAME_XACML20 = new QName(SAMLXACMLConstants.SAML2_XACML20P_NS, TYPE_LOCAL_NAME,
           SAMLXACMLConstants.SAML2_XACMLPROTOCOL_PREFIX);
  
   /** CombinePolicies attribute name. */
   public static final String COMBINEPOLICIES_ATTRIB_NAME = "CombinePolicies";

   /**
    * Returns if the PDP can combine policies from the query and local policies.
    * 
    * @return XSBooleanValue true if the PDP can combine policies from the query and locally
    */
   public XSBooleanValue getCombinePolicies();

   /**
    * Gets the request of the query.
    * 
    * @return RequestContext The request inside the query
    */
   public RequestContext getRequest();
 
   /**
    * Returns if the PDP can combine policies from the query and local policies.
    * 
    * @return true if the PDP can combine policies from the query and locally
    */
   public boolean isCombinePolicies();

   /**
    * Sets if the PDP can combine policies from this query and the one locally.
    * 
    * @param combinePolicies If true then the PDP can combine policies from this query and the one locally
    */
   public void setCombinePolicies(XSBooleanValue combinePolicies);

   /**
    * Set's the XACML Request.
    * 
    * @param request The request of the decision query
    */
   public void setRequest(RequestContext request);
}