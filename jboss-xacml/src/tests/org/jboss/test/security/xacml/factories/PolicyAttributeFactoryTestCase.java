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
package org.jboss.test.security.xacml.factories;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.model.policy.AttributeDesignatorType;
import org.jboss.security.xacml.core.model.policy.SubjectAttributeDesignatorType;
import org.jboss.security.xacml.factories.PolicyAttributeFactory;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XMLSchemaConstants;

/**
 * TestCase for <code>PolicyAttributeFactory</code>
 * 
 * @author Marcus Moyses
 * @since Mar 18, 2008
 */
public class PolicyAttributeFactoryTestCase extends TestCase
{

   public void testCreateAttributeDesignatorType1() throws Exception
   {
      AttributeDesignatorType adt = PolicyAttributeFactory.createAttributeDesignatorType(
            XACMLConstants.ATTRIBUTEID_ACTION_ID, XMLSchemaConstants.DATATYPE_STRING, null, false);
      assertEquals("AttributeId?", XACMLConstants.ATTRIBUTEID_ACTION_ID, adt.getAttributeId());
      assertEquals("DataType?", XMLSchemaConstants.DATATYPE_STRING, adt.getDataType());
      assertEquals("MustBePresent?", false, adt.isMustBePresent());
      assertNull("Issuer?", adt.getIssuer());
   }

   public void testCreateAttributeDesignatorType2() throws Exception
   {
      AttributeDesignatorType adt = PolicyAttributeFactory.createAttributeDesignatorType(
            XACMLConstants.ATTRIBUTEID_CURRENT_DATE, XMLSchemaConstants.DATATYPE_DATE, "org.jboss", true);
      assertEquals("AttributeId?", XACMLConstants.ATTRIBUTEID_CURRENT_DATE, adt.getAttributeId());
      assertEquals("DataType?", XMLSchemaConstants.DATATYPE_DATE, adt.getDataType());
      assertEquals("MustBePresent?", true, adt.isMustBePresent());
      assertEquals("Issuer?", "org.jboss", adt.getIssuer());
   }

   public void testCreateSubjectAttributeDesignatorType1() throws Exception
   {
      SubjectAttributeDesignatorType adt = PolicyAttributeFactory.createSubjectAttributeDesignatorType(
            XACMLConstants.ATTRIBUTEID_ACTION_ID, XMLSchemaConstants.DATATYPE_STRING, null, false, null);
      assertEquals("AttributeId?", XACMLConstants.ATTRIBUTEID_ACTION_ID, adt.getAttributeId());
      assertEquals("DataType?", XMLSchemaConstants.DATATYPE_STRING, adt.getDataType());
      assertEquals("MustBePresent?", false, adt.isMustBePresent());
      assertNull("Issuer?", adt.getIssuer());
      assertEquals("SubjectCategory?", XACMLConstants.ATTRIBUTEID_ACCESS_SUBJECT, adt.getSubjectCategory());
   }

   public void testCreateSubjectAttributeDesignatorType2() throws Exception
   {
      SubjectAttributeDesignatorType adt = PolicyAttributeFactory.createSubjectAttributeDesignatorType(
            XACMLConstants.ATTRIBUTEID_CURRENT_DATE, XMLSchemaConstants.DATATYPE_DATE, "org.jboss", true,
            XACMLConstants.ATTRIBUTEID_CODEBASE);
      assertEquals("AttributeId?", XACMLConstants.ATTRIBUTEID_CURRENT_DATE, adt.getAttributeId());
      assertEquals("DataType?", XMLSchemaConstants.DATATYPE_DATE, adt.getDataType());
      assertEquals("MustBePresent?", true, adt.isMustBePresent());
      assertEquals("Issuer?", "org.jboss", adt.getIssuer());
      assertEquals("SubjectCategory?", XACMLConstants.ATTRIBUTEID_CODEBASE, adt.getSubjectCategory());
   }
}
