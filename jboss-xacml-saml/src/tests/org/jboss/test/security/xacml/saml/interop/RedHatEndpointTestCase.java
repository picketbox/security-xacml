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
package org.jboss.test.security.xacml.saml.interop;

import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;

import junit.framework.TestCase;

import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.saml.integration.opensaml.core.JBossXACMLSAMLConfiguration;
import org.jboss.security.xacml.saml.integration.opensaml.request.JBossSAMLRequest;
import org.jboss.security.xacml.saml.integration.opensaml.request.JBossSAMLResponse;
import org.jboss.security.xacml.saml.integration.opensaml.types.XACMLAuthzDecisionStatementType;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AssertionImpl;
import org.opensaml.xml.util.XMLHelper;
 
/**
 *  Test the JBoss endpoint
 *  @author Anil.Saldhana@redhat.com
 *  @since  Apr 2, 2008 
 *  @version $Revision$
 */
public class RedHatEndpointTestCase extends TestCase
{
   String loc = "http://localhost:8080/jboss/SOAPServlet";
   
   boolean shouldTest = false;
   
   protected void setUp() throws Exception
   {
      JBossXACMLSAMLConfiguration.initialize(); 
      if(shouldTest == false)
         System.out.println("TEST is disabled");
   }
   
   public void testRequest01_01() throws Exception
   {

      /**
      <!-- **************************************************************** -->
      <!-- Test case 1-01: Should be Perm: Dr A has all reqd perms          -->
      <!-- **************************************************************** -->
      **/
      if(shouldTest)
      { 
         System.setProperty("debug","true");
         JBossSAMLRequest samlRequest = new JBossSAMLRequest();
         ClassLoader tcl = Thread.currentThread().getContextClassLoader();
         InputStream is = tcl.getResourceAsStream("test/requests/interop/rsaconf08/XacmlRequest-01-01.xml");
         assertNotNull(is);
         SAMLObject samlObject = samlRequest.getSAMLRequest(is);
         
         URL url = new URL(loc);
         URLConnection conn = url.openConnection();
         conn.setDoOutput(true);
         OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
         wr.write(XMLHelper.nodeToString(samlObject.getDOM()));
         wr.flush();
         
         JBossSAMLResponse samlResponse = new JBossSAMLResponse();
         Response response = (Response) samlResponse.getSAMLResponse(conn.getInputStream());
         System.out.println(XMLHelper.prettyPrintXML(response.getDOM()));       
         
         Assertion assertion = response.getAssertions().get(0);
         AssertionImpl aimpl = (AssertionImpl) assertion;
         XACMLAuthzDecisionStatementType xtype = (XACMLAuthzDecisionStatementType) aimpl.getStatements().get(0);
         ResponseContext rc = xtype.getResponse();
         assertEquals(XACMLConstants.DECISION_PERMIT,rc.getDecision());
      } 
   } 
}