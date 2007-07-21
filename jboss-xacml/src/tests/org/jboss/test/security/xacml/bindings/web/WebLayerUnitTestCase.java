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
import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;

//$Id$

/**
 *  Unit Tests for the Web bindings
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 10, 2007 
 *  @version $Revision$
 */
public class WebLayerUnitTestCase extends TestCase
{
   private boolean debug = false; //Enable for request trace
   
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
      Group grp = this.getRoleGroup("developer");
      
      String requestURI = "http://test/developer-guide.html";
      HttpRequestUtil util = new HttpRequestUtil();
      HttpServletRequest req = util.createRequest(p, requestURI); 
      
      //Check PERMIT condition
      WebPEP pep = new WebPEP();
      RequestContext request = pep.createXACMLRequest(req, p, grp);
      if(debug)
        request.marshall(System.out);
      
      assertEquals("Access Allowed?", XACMLConstants.DECISION_PERMIT,
            getDecision(pdp,request)); 
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
      Group grp = this.getRoleGroup("imposter");
      String requestURI = "http://test/developer-guide.html";
      HttpRequestUtil util = new HttpRequestUtil();
      HttpServletRequest req = util.createRequest(p, requestURI); 
      
      //Check DENY condition
      WebPEP pep = new WebPEP();
      RequestContext request = pep.createXACMLRequest(req, p, grp);
      request.marshall(System.out);
      
      assertEquals("Access Disallowed?", XACMLConstants.DECISION_DENY,
            getDecision(pdp,request));  
   }  
   
   private PolicyDecisionPoint getPDP()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("test/config/webConfig.xml");
      assertNotNull("InputStream != null", is);
      
      return new JBossPDP(is);  
   }
   
   private int getDecision(PolicyDecisionPoint pdp, RequestContext request) throws Exception
   { 
      ResponseContext response = pdp.evaluate(request);
      assertNotNull("Response is not null", response);
      return response.getDecision(); 
   }
   
   private Group getRoleGroup( final String roleName)
   {
      return new Group() {

         private Vector vect = new Vector();
         public boolean addMember(final Principal principal)
         { 
            return vect.add(principal);
         }

         public boolean isMember(Principal principal)
         { 
            return vect.contains(principal);
         }

         public Enumeration<? extends Principal> members()
         { 
            vect.add(new Principal()
            {

               public String getName()
               { 
                  return roleName;
               }});
            return vect.elements();
         }

         public boolean removeMember(Principal principal)
         { 
            return vect.remove(principal);
         }

         public String getName()
         { 
            return "ROLES";
         }
       }; 
   } 
}
