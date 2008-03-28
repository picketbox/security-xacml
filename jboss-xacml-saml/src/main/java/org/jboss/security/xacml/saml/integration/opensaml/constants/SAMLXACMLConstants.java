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
package org.jboss.security.xacml.saml.integration.opensaml.constants;

import javax.xml.namespace.QName;
 

/**
 *  SAML v2.0 XACML constants
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public interface SAMLXACMLConstants
{

   String SAML2_XACML_ATTRIBUTE_NS = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML";
  
   /** XACML attribute profile spec. */
   QName SAML_DATATYPE_ATTRIB = new QName(SAML2_XACML_ATTRIBUTE_NS, "DataType", "xacmlprof");

   /** The prefix for saml-xacml assertion. */
   String SAML2_XACMLASSERTION_PREFIX = "xacml-saml";

   /** The prefix for saml20-xacml protocol. */
   String SAML2_XACMLPROTOCOL_PREFIX = "xacml-samlp";
   
   String SAMLP = "urn:oasis:xacml:2.0:saml:protocol:schema:os";

   /** The namespaces for XACML 1.0 SAML 2.0 protocol. */
   String SAML2_XACML10P_NS = "urn:oasis:names:tc:xacml:1.0:profile:saml2.0:v2:schema:protocol";

   /** The namespaces for XACML 1.0 SAML 2.0 assertion. */
   String SAML2_XACML10_NS = "urn:oasis:names:tc:xacml:1.0:profile:saml2.0:v2:schema:assertion";

   /** The namespace for XACML 1.1 SAML 2.0 protocol. */
   String SAML2_XACML1_1P_NS = "urn:oasis:names:tc:xacml:1.1:profile:saml2.0:v2:schema:protocol";

   /** The namespace for XACML 1.1 SAML 2.0 assertion. */
   String SAML2_XACML1_1_NS = "urn:oasis:names:tc:xacml:1.1:profile:saml2.0:v2:schema:assertion";

   /** The namespaces for XACML 2.0 SAML 2.0 protocol. */
   String SAML2_XACML20P_NS = "urn:oasis:names:tc:xacml:2.0:profile:saml2.0:v2:schema:protocol";

   /** The namespaces for XACML 2.0 SAML 2.0 assertion. */
   String SAML2_XACML20_NS = "urn:oasis:names:tc:xacml:2.0:profile:saml2.0:v2:schema:assertion";
}