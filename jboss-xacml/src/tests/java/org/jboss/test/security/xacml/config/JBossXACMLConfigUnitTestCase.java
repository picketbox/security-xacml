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
package org.jboss.test.security.xacml.config;

import java.net.URL;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.jaxb.LocatorType;
import org.jboss.security.xacml.jaxb.LocatorsType;
import org.jboss.security.xacml.jaxb.PDP;
import org.jboss.security.xacml.jaxb.PoliciesType;
import org.jboss.security.xacml.jaxb.PolicySetType;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;

//$Id$

/**
 *  Test the import of the config file driving JBossXACML
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 5, 2007 
 *  @version $Revision$
 */
public class JBossXACMLConfigUnitTestCase extends TestCase
{
   public void testBasicPolicySetConfig() throws Exception
   {
      JAXBContext jc = JAXBContext.newInstance("org.jboss.security.xacml.jaxb");
      assertNotNull("JAXBContext is !null", jc);
      Unmarshaller u = jc.createUnmarshaller();
      //Validate against schema
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      URL schemaURL = tcl.getResource("schema/jbossxacml-2.0.xsd");
      assertNotNull("Schema URL != null", schemaURL);
      SchemaFactory scFact = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      Schema schema = scFact.newSchema(schemaURL);
      u.setSchema(schema);

      URL configFile = tcl.getResource("test/config/basicPolicySetConfig.xml");
      JAXBElement<?> j = (JAXBElement<?>) u.unmarshal(configFile);
      assertNotNull("JAXBElement is !null", j);
      PDP pdp = (PDP) j.getValue();
      assertNotNull("PDP is not null", pdp);

      //Validate Policies
      PoliciesType pts = pdp.getPolicies();
      assertNotNull("PoliciesType is not null", pts);
      List<PolicySetType> pst = pts.getPolicySet();
      assertNotNull("PolicySetType is not null", pst);
      assertEquals("1 PolicySet", 1, pst.size());
      PolicySetType psetType = pst.get(0);
      String loc = psetType.getLocation();
      assertTrue("Location of PolicySet is >0", loc.length() > 0);
      assertEquals("PolicyType is null", 0, pts.getPolicy().size());

      //Validate Locators
      LocatorsType lts = pdp.getLocators();
      assertNotNull("LocatorsType != null", lts);
      List<LocatorType> lt = lts.getLocator();
      assertNotNull("LocatorType != null", lt);
      assertEquals("LocatorType != null", 1, lt.size());
   }

   /**
    * Test the URL version of the PDP construction
    * @throws Exception
    */
   public void testPDPConfig() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      URL configFile = tcl.getResource("test/config/interopPolicySetConfig.xml");
      assertNotNull("configFile != null", configFile);
      PolicyDecisionPoint pdp = new JBossPDP(configFile);
      XACMLTestUtil.validateInteropCases(pdp);
   }
}
