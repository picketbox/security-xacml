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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;
import org.junit.Test;


/**
 * Unit test the {@code FileSystemAttributeLocator}
 * @author Anil.Saldhana@redhat.com
 * @since Aug 31, 2010
 */
public class FileSystemAttributeLocatorUnitTestCase
{
   @Test
   public void testPDPUsingDatabaseResourceAttributeLocator() throws Exception
   { 
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      InputStream is = tcl.getResourceAsStream("locators/attrib/filesystem_attrib_locator-config.xml");
      assertNotNull("Inputstream is not null?", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      ResponseContext response = XACMLTestUtil.getResponse(pdp,"locators/attrib/attribLocatorResourceAttribute-request.xml"); 
      int decision = response.getDecision();
      assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
   }
   
   @Test
   public void testPDPUsingDatabaseSubjectAttributeLocator() throws Exception
   { 
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();

      InputStream is = tcl.getResourceAsStream("locators/attrib/filesystem_attrib_locator-config.xml");
      assertNotNull("Inputstream is not null?", is);
      PolicyDecisionPoint pdp = new JBossPDP(is);
      ResponseContext response = XACMLTestUtil.getResponse(pdp,"locators/attrib/attribLocatorSubjectAttribute-request.xml"); 
      int decision = response.getDecision();
      assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
   }
}