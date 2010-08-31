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
package org.jboss.test.security.xacml.core.request;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.Subject;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;
import org.junit.Test;

/**
 * Unit Test various possibilities with xacml request
 * @author Anil.Saldhana@redhat.com
 * @since Aug 30, 2010
 */
public class XACMLRequestUnitTestCase
{

   private static String REQUEST1 = "test/requests/interop/scenario2-testcase1-request.xml";
   private static String REQUEST2 = "test/requests/interop/scenario2-testcase2-request.xml";
   
   @Test
   public void testEquality() throws Exception
   {
      RequestContext requestContext1 = XACMLTestUtil.getRequest( REQUEST1 );
      RequestCtx xacmlRequest1 = requestContext1.get( XACMLConstants.REQUEST_CTX );
      
      RequestContext requestContext2 = XACMLTestUtil.getRequest( REQUEST2 );
      RequestCtx xacmlRequest2 = requestContext2.get( XACMLConstants.REQUEST_CTX );
      
      RequestContext copyRequestContext1 = XACMLTestUtil.getRequest( REQUEST1 );
      RequestCtx copyXacmlRequest1 = copyRequestContext1.get( XACMLConstants.REQUEST_CTX );
      
      RequestContext copyRequestContext2 = XACMLTestUtil.getRequest( REQUEST2 );
      RequestCtx copyXacmlRequest2 = copyRequestContext2.get( XACMLConstants.REQUEST_CTX );
      
      assertEquals( "Requests are equal", xacmlRequest1, copyXacmlRequest1 );
      assertEquals( "Requests are equal", xacmlRequest2, copyXacmlRequest2 ); 
   }
   
   @Test
   public void testDuplicateAttributes() throws Exception
   {
      RequestContext requestContext = XACMLTestUtil.getRequest( "test/requests/DuplicateAttributes.xml" );
      RequestCtx xacmlRequest = requestContext.get( XACMLConstants.REQUEST_CTX );
      
      List subjectSet = xacmlRequest.getSubjectsAsList();
      Subject subject = (Subject) subjectSet.iterator().next();
      List attributes = subject.getAttributesAsList();
      assertEquals( "Attribs are 3", 3, attributes.size() ); 
   }
}