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
package org.jboss.test.security.sunxacml.request;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.Subject;

/**
 * Unit test to read xacml requests
 * @author Anil.Saldhana@redhat.com
 * @since Mar 30, 2009
 */
public class RequestReadUnitTestCase extends TestCase
{ 
   @SuppressWarnings("rawtypes")
   public void testMultipleResourceIds() throws Exception
   {
      String fileName = "src/test/resources/requests/multiple-resourceid.xml";
      
      RequestCtx req = RequestCtx.getInstance(new FileInputStream(new File(fileName)));
      assertNotNull("Request is not null", req);
      List resources = req.getResourceAsList();
      assertTrue("Multiple resources", resources.size() > 1);
   }
   
   @SuppressWarnings("rawtypes")
   public void testDuplicateAttributes() throws Exception
   {
      String fileName = "src/test/resources/requests/DuplicateAttributes.xml";
      
      RequestCtx req = RequestCtx.getInstance(new FileInputStream(new File(fileName)));
      assertNotNull("Request is not null", req);
      List subjects = req.getSubjectsAsList();
      Subject subject = (Subject) subjects.get(0);
      List attribs = subject.getAttributesAsList(); 
      assertEquals( 3, attribs.size() );
   }
}