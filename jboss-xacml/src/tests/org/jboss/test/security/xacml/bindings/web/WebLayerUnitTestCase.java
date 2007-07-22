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
package org.jboss.test.security.xacml.bindings.web;

import java.io.InputStream;
import java.security.Principal;
import java.security.acl.Group;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;

//$Id$

/**
 *  Unit Tests for the Web bindings
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 10, 2007 
 *  @version $Revision$
 */
public class WebLayerUnitTestCase extends TestCase
{
   //Enable for request trace
   private boolean debug = "true".equals(System.getProperty("debug","false")); 
   
   public void testWebBinding() throws Exception
   { 
      PolicyDecisionPoint pdp = getPDP(); 
      assertNotNull("JBossPDP is != null", pdp);
      
      Principal p = new Principal()
      { 
         public String getName()
         { 
            return "testuser";
         } 
      };

      //Create Role Group
      Group grp = XACMLTestUtil.getRoleGroup("developer");
      
      String requestURI = "http://test/developer-guide.html";
      HttpRequestUtil util = new HttpRequestUtil();
      HttpServletRequest req = util.createRequest(p, requestURI); 
      
      //Check PERMIT condition
      WebPEP pep = new WebPEP();
      RequestContext request = pep.createXACMLRequest(req, p, grp);
      if(debug)
        request.marshall(System.out);
      
      assertEquals("Access Allowed?", XACMLConstants.DECISION_PERMIT,
            XACMLTestUtil.getDecision(pdp,request)); 
   }
   
   public void testNegativeAccessWebBinding() throws Exception
   {
      PolicyDecisionPoint pdp = getPDP(); 
      assertNotNull("JBossPDP is != null", pdp);
      Principal p = new Principal()
      { 
         public String getName()
         { 
            return "testuser";
         } 
      };

      //Create Role Group
      Group grp = XACMLTestUtil.getRoleGroup("imposter");
      String requestURI = "http://test/developer-guide.html";
      HttpRequestUtil util = new HttpRequestUtil();
      HttpServletRequest req = util.createRequest(p, requestURI); 
      
      //Check DENY condition
      WebPEP pep = new WebPEP();
      RequestContext request = pep.createXACMLRequest(req, p, grp);
      if(debug)
         request.marshall(System.out);
      
      assertEquals("Access Disallowed?", XACMLConstants.DECISION_DENY,
            XACMLTestUtil.getDecision(pdp,request));  
   }  
   
   private PolicyDecisionPoint getPDP()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("test/config/webConfig.xml");
      assertNotNull("InputStream != null", is);
      
      return new JBossPDP(is);  
   }  
}
