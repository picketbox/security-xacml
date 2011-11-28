/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
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
/**
 * 
 */
package org.jboss.test.security.xacml.core;

import java.io.InputStream;

import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.Assert;

import org.jboss.security.xacml.core.JBossRequestContext;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Dan Gradl
 * @since Nov 24, 2011
 */
public class JBossRequestContextTest
{

   @Test
   public void testAsElement() throws Exception
   {
      JBossRequestContext context = new JBossRequestContext();

      //Create a request Document
      InputStream is = Thread.currentThread().getContextClassLoader()
            .getResourceAsStream("test/requests/SimpleRequest.xml");
      String contextSchema = "urn:oasis:names:tc:xacml:2.0:context:schema:os";
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setIgnoringComments(true);
      Document doc = factory.newDocumentBuilder().parse(is);

      //Get as element
      Element element = context.asElement(doc);

      //Assert results
      Assert.assertNotNull("Element should not be null", element);

      //Just a test to see if it can parse out a value
      Element resourceElement = (Element) element.getElementsByTagName("Resource").item(0);
      String attributeId = resourceElement.getElementsByTagName("Attribute").item(0).getAttributes()
            .getNamedItem("AttributeId").getNodeValue();
      Assert.assertEquals("AttributeId not as expected", "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
            attributeId);
   }

}
