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
package org.jboss.test.security.xacml.core.model;

import org.jboss.security.xacml.core.model.context.AttributeType; 
import org.jboss.security.xacml.core.model.context.AttributeValueType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;

import junit.framework.TestCase;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Jul 31, 2009
 */
public class RequestContextAttributeFactoryUnitTestCase extends TestCase
{
   public void testMultiValuedAttribute()
   {
      String attributeId = "urn:va:xacml:2.0:interop:rsa8:subject:hl7:permission";
      String dataType = "http://www.w3.org/2001/XMLSchema#string";
      String issuer = "testissuer";
      
      //Create a multi-valued attribute - hl7 permissions
      String[] values = new String[] {"urn:va:xacml:2.0:interop:rsa8:hl7:prd-010",
            "urn:va:xacml:2.0:interop:rsa8:hl7:prd-012",
            "urn:va:xacml:2.0:interop:rsa8:hl7:prd-017",
            "urn:va:xacml:2.0:interop:rsa8:hl7:prd-005",
            "urn:va:xacml:2.0:interop:rsa8:hl7:prd-003",
            "urn:va:xacml:2.0:interop:rsa8:hl7:prd-009",
            "urn:va:xacml:2.0:interop:rsa8:hl7:prd-006"};
      
      AttributeType multi = RequestAttributeFactory.createMultiValuedAttributeType(attributeId, 
            issuer, dataType, values);
      assertNotNull("Attribute is not null", multi);
      AttributeValueType avt = multi.getAttributeValue().get(0);
      assertEquals(7 ,avt.getContent().size());
   }

}