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

import java.util.Date;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.attr.TimeAttribute;

/**
 * Unit tests for the Time Attribute
 * @author Anil.Saldhana@redhat.com
 * @since Mar 30, 2009
 */
public class TimeAttributeUnitTestCase extends TestCase
{ 
   public void testTime() throws Exception
   {
      TimeAttribute end = TimeAttribute.getInstance("23:59:00-08:00");
      TimeAttribute now = TimeAttribute.getInstance("16:50:07.091000000-05:00"); 
      
      Date nowDate = now.getValue();
      Date endDate = end.getValue();
      
      assertTrue("4:50 PM CDT is before 11:59 PDT", nowDate.before(endDate)); 
      
      end = TimeAttribute.getInstance("01:59:00-08:00");
      now = TimeAttribute.getInstance("03:59:00-06:00");
      
      nowDate = now.getValue();
      endDate = end.getValue();
      
      assertFalse("03:59 central is not before 01:59 PDT", nowDate.before(endDate) );
      
      end = TimeAttribute.getInstance("03:59:00-08:00");
      now = TimeAttribute.getInstance("03:59:00-08:00");
      
      nowDate = now.getValue();
      endDate = end.getValue();
      
      assertFalse("03:59 PDT is not before 03:59 PDT", nowDate.before(endDate) );
   } 
}
