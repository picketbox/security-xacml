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
package org.jboss.test.security.sunxacml.attr;

import java.net.URI;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.attr.DateTimeAttribute;
import org.jboss.security.xacml.sunxacml.attr.StringAttribute;
import org.jboss.security.xacml.sunxacml.ctx.Attribute;

/**
 * Test the Attribute Construct
 * @author Anil.Saldhana@redhat.com
 * @since Oct 29, 2008
 */
public class AttributeUnitTestCase extends TestCase
{ 
   /**
    * SECURITY-206: Attribute type not set in constructor
    * @throws Exception
    */
   public void testAttributeTypeInCTR() throws Exception
   {
      URI RESOURCE_URI = new URI("urn:oasis:names:tc:xacml:1.0:resource:resource-id");
      AttributeValue attributeValue = new StringAttribute("TestAttribute");
      
      Attribute attribute = new Attribute(RESOURCE_URI, "somepackage" ,
            new DateTimeAttribute(), attributeValue);
      
      assertNotNull("Attribute type", attribute.getType());
   } 
}