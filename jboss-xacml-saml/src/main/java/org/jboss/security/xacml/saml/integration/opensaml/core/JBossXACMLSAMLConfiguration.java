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
package org.jboss.security.xacml.saml.integration.opensaml.core;

import javax.xml.namespace.QName;

import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeImplBuilder;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeUnMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionStatementTypeImplBuilder;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionStatementTypeMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionStatementTypeUnMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.opensaml.Configuration;

/**
 *  Configuration class to initialize any configuration
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 3, 2008 
 *  @version $Revision$
 */
public class JBossXACMLSAMLConfiguration
{
   /**
    * Initializes the JBoss XACML-SAML Integration layer
    * @throws Exception
    */
   public static void initialize() throws Exception
   {
      org.opensaml.DefaultBootstrap.bootstrap(); 
      
      //Register a qname prefixed query type
      Configuration.registerObjectProvider(
            XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20, 
            new XACMLAuthzDecisionQueryTypeImplBuilder(), 
            new XACMLAuthzDecisionQueryTypeMarshaller(), 
            new XACMLAuthzDecisionQueryTypeUnMarshaller(), 
            null);
      
      //Register a non-qname prefixed query type
      Configuration.registerObjectProvider(
            new QName(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_LOCAL_NAME), 
            new XACMLAuthzDecisionQueryTypeImplBuilder(), 
            new XACMLAuthzDecisionQueryTypeMarshaller(), 
            new XACMLAuthzDecisionQueryTypeUnMarshaller(), 
            null);
      
      //Register a qname prefixed decision statement type
      Configuration.registerObjectProvider(
            XACMLAuthzDecisionStatementType.DEFAULT_ELEMENT_NAME_XACML20, 
            new XACMLAuthzDecisionStatementTypeImplBuilder(), 
            new XACMLAuthzDecisionStatementTypeMarshaller(), 
            new XACMLAuthzDecisionStatementTypeUnMarshaller(), 
            null);

      //Register a non-qname prefixed decision statement type
      Configuration.registerObjectProvider(
            new QName(XACMLAuthzDecisionStatementType.DEFAULT_ELEMENT_LOCAL_NAME), 
            new XACMLAuthzDecisionStatementTypeImplBuilder(), 
            new XACMLAuthzDecisionStatementTypeMarshaller(), 
            new XACMLAuthzDecisionStatementTypeUnMarshaller(), 
            null); 
   }
}
