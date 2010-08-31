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
package org.jboss.test.security.xacml.interop.himss09;

import java.io.InputStream;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;

import junit.framework.TestCase;

/**
 * Himss09 Unit Test Case
 * @author Anil.Saldhana@redhat.com
 * @since Mar 30, 2009
 */
public class Himss09UnitTestCase extends TestCase
{
   public void testPermit() throws Exception
   {    
      validateCase( getResponse( "himss-request-01.xml" ),  XACMLConstants.DECISION_PERMIT ); 
   }

   private PolicyDecisionPoint getPDP()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream( "test/config/himss09-interop-config.xml" );
      assertNotNull( "InputStream != null", is );

      return new JBossPDP(is);
   }
   
   private ResponseContext getResponse(String loc) throws Exception
   {
      loc = "test/requests/interop/himss09/" + loc;
      return XACMLTestUtil.getResponse( getPDP(), loc );
   }
   
   private void validateCase( ResponseContext response, int decisionval ) throws Exception
   {
      int decision = response.getDecision();
      
      switch( decisionval )
      {
         case XACMLConstants.DECISION_PERMIT: 
            assertEquals( "PERMIT?", XACMLConstants.DECISION_PERMIT, decision );
            break;
         case XACMLConstants.DECISION_DENY:
            assertEquals( "DENY?", XACMLConstants.DECISION_DENY, decision );
            break;
         default: fail( "wrong value" );
      }  
   } 
}