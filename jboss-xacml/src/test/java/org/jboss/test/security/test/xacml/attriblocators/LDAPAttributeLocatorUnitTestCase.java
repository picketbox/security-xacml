/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
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
package org.jboss.test.security.test.xacml.attriblocators;

import java.io.File;
import java.io.InputStream;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;
import org.jboss.test.security.xacml.ldap.OpenDSUnitTestAdapter;
import org.junit.Test;

/**
 * Unit test the {@code LDAPAttributeLocator}
 * @author Anil.Saldhana@redhat.com
 * @since Aug 25, 2010
 */
public class LDAPAttributeLocatorUnitTestCase extends OpenDSUnitTestAdapter
{
   public LDAPAttributeLocatorUnitTestCase(String name)
   {
      super(name); 
   }

   @Override
   protected void setUp() throws Exception
   {
      super.setUp();
      // Let us add the ldap.ldif
      String fileName = targetDir + "test" + fs + "ldif" + fs + "ldap-attrib.ldif";
      boolean op = util.addLDIF(serverHost, port, adminDN, adminPW, new File(fileName).toURI().toURL());
      assertTrue(op);   
   }
   
   @Test
   public void testPDPUsingLDAPResourceAttributeLocator() throws Exception
   {   
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      InputStream is = tcl.getResourceAsStream("locators/attrib/ldap_resource_attrib_locator-config.xml");
      assertNotNull("Inputstream is not null?", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      ResponseContext response = XACMLTestUtil.getResponse(pdp,"locators/attrib/attribLocatorResourceAttribute-request.xml"); 
      int decision = response.getDecision();
      assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
   }
   
   @Test
   public void testPDPUsingLDAPSubjectAttributeLocator() throws Exception
   { 
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      InputStream is = tcl.getResourceAsStream("locators/attrib/ldap_subject_attrib_locator-config.xml");
      assertNotNull("Inputstream is not null?", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      ResponseContext response = XACMLTestUtil.getResponse(pdp,"locators/attrib/attribLocatorSubjectAttribute-request.xml"); 
      int decision = response.getDecision();
      assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
   }
}