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
package org.jboss.test.security.xacml.saml;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.PDPConfiguration;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeImplBuilder;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.impl.XACMLAuthzDecisionQueryTypeUnMarshaller;
import org.jboss.security.xacml.saml.integration.opensaml.request.SAMLRequest;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.util.XMLHelper;
 
/**
 *  Unit Test for the Opensaml saml/xacml
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class SAMLXACMLUnitTestCase extends TestCase
{
   protected void setUp() throws Exception
   {
     org.opensaml.DefaultBootstrap.bootstrap(); 
     Configuration.registerObjectProvider(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20, 
           new XACMLAuthzDecisionQueryTypeImplBuilder(), 
           new XACMLAuthzDecisionQueryTypeMarshaller(), 
           new XACMLAuthzDecisionQueryTypeUnMarshaller(), 
           null);
   }
   
   public void testSAMLXACMLRequestRead() throws Exception
   {
      //Install Custom Attributes
      PDPConfiguration.installSingleValueAttribute("urn:va:names:xacml:2.0:subject:ien");
      
      SAMLRequest request = new SAMLRequest();
      SAMLObject samlObject = request.getSAMLRequest("src/tests/resources/saml/xacmlrequest.xml");
      assertNotNull(samlObject);
      assertTrue(samlObject instanceof XACMLAuthzDecisionQueryType);
      XACMLAuthzDecisionQueryType xacmlRequest = (XACMLAuthzDecisionQueryType)samlObject;
      RequestContext requestType = xacmlRequest.getRequest();
      assertNotNull("XACML Request is not null", requestType);
      
      XMLObject xmlObject = xacmlRequest;
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
      //surefire plugin issue
      try
      {
         System.out.println(XMLHelper.prettyPrintXML(marshaller.marshall(xmlObject))); 
      }
      catch(Exception e)
      {
         e.printStackTrace();
      }
   }
  
   public void testSAMLRequestRead() throws Exception
   {
      SAMLRequest request = new SAMLRequest();
      SAMLObject samlObject = request.getSAMLRequest("src/tests/resources/saml/samlrequest.xml");
      assertNotNull(samlObject);
   }
}