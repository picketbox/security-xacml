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

import java.util.UUID;

import junit.framework.TestCase;

import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.saml.integration.opensaml.core.JBossXACMLSAMLConfiguration;
import org.jboss.security.xacml.saml.integration.opensaml.request.JBossSAMLRequest;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionQueryType;
import org.jboss.security.xacml.saml.integration.opensaml.util.SAML2Util;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.RequestAbstractType;

/**
 *  Tests for SAMLRequest read
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class SAMLRequestUnitTestCase extends TestCase
{
   private SAML2Util util = new SAML2Util();
   
   protected void setUp() throws Exception
   {
      JBossXACMLSAMLConfiguration.initialize(); 
   }
   
   public void testSAMLRequest01_01() throws Exception
   {
      JBossSAMLRequest samlRequest = new JBossSAMLRequest();
      String loc = "src/test/resources/test/requests/interop/rsaconf08/XacmlRequest-01-01.xml";
      SAMLObject samlObject = samlRequest.getSAMLRequest(loc);
      XACMLAuthzDecisionQueryType xacmlRequest = (XACMLAuthzDecisionQueryType)samlObject;
      RequestContext requestContext = xacmlRequest.getRequest();
      assertNotNull("XACML Request Context is not null", requestContext);
   }
   
   public void testSAMLRequestConstruction()
   {
      DateTime issueInstant = util.getIssueInstant(); 
      String requestId = UUID.randomUUID().toString();
      JBossSAMLRequest samlRequest = new JBossSAMLRequest();
      Object request = samlRequest.buildRequest(issueInstant, requestId, "anil");
      assertTrue(request instanceof RequestAbstractType);
      
      RequestAbstractType rat = (RequestAbstractType) request;
      assertEquals(issueInstant,rat.getIssueInstant());
      assertEquals(requestId,rat.getID());
      assertEquals("anil", rat.getIssuer().getValue());
   }

}