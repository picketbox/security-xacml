/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.security.test.xacml;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.util.ArrayList;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.ConfigurationStore;
import org.jboss.security.xacml.sunxacml.PDP;
import org.jboss.security.xacml.sunxacml.PDPConfig;
import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.ctx.Status;

//$Id: XACMLUnitTestCase.java 45725 2006-06-21 17:19:15Z asaldhana $

/**
 *  Unit Tests for the XACML Integration
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 26, 2006 
 *  @version $Revision: 45725 $
 */
public class XACMLUnitTestCase extends TestCase
{
   /**
    * There are basic xacml conformance tests in the resources folder(security/xacml)
    * with the format testX where X is an integer in (firstTest,numberOfTests}.
    * If you need to run a particular test - make both these variables to be
    * the number of the test. So to run test6, both firstTest=6 and
    * numberOfTests=6
    */
   private int firstTest = 1;

   private int numberOfTests = 17;

   //True: Response will be dumped to System.out
   private boolean debug = false;

   public XACMLUnitTestCase(String name)
   {
      super(name);
   }

   public void testPDPConstruction() throws Exception
   {
      assertNotNull("PDP != null", getBasicPDP());
   }

   public void testPDPResponse() throws Exception
   {
      for (int i = firstTest; i <= numberOfTests; i++)
      {
         String[] policyFiles = new String[]
         {getPolicyFile(i)};
         PDP pdp = new PDP(new PDPConfig(XACMLUtil.getAttributeFinder(), XACMLUtil.getPolicyFinder(policyFiles), null));
         assertNotNull("PDP != null", pdp);
         ResponseCtx first = processRequest(pdp, getRequestFile(i));
         assertNotNull("Response != null", first);
         //Print out the response to the System.Out
         XACMLUtil.logResponseCtxToSystemOut(first, debug);
         ResponseCtx second = ResponseCtx.getInstance(new FileInputStream(getResponseFile(i)));
         try
         {
            XACMLUtil.assertEquals(first, second);
         }
         catch (Exception e)
         {
            Exception enew = new Exception("Test#" + i + "::" + e.getMessage());
            enew.initCause(e);
            throw enew;
         }
      }
   }

   /**
    * Obtain a very basic PDP
    * @return
    * @throws Exception
    */
   private PDP getBasicPDP() throws Exception
   {
      String p = "security/xacml/basicConfig.xml";
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      URL url = tcl.getResource(p);
      File file = new File(url.getPath());
      ConfigurationStore store = new ConfigurationStore(file);
      store.useDefaultFactories();
      return new PDP(store.getDefaultPDPConfig());
   }

   /**
    * Ask the PDP to evaluate the input request file
    * @param pdp
    * @param requestFile
    * @return
    * @throws Exception
    */
   private ResponseCtx processRequest(PDP pdp, String requestFile) throws Exception
   {
      ResponseCtx response = null;

      try
      {
         response = pdp.evaluate(RequestCtx.getInstance(new FileInputStream(requestFile)));
      }
      catch (ParsingException pse)
      {
         response = getSyntaxErrorResponseCtx();
      }
      return response;
   }

   /**
    * Get the String that represents the temp file
    * for the Policy 1
    * @return
    */
   private String getPolicyFile(int num) throws Exception
   {
      String p1 = "security/xacml/test" + num + "/policy.xml";
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      URL url = tcl.getResource(p1);
      assertNotNull("policy file " + p1 + "  null", url);
      return url.getPath();
   }

   /**
    * Get the String that represents the file
    * for the Request File 
    * @return
    */
   private String getRequestFile(int num) throws Exception
   {
      String p1 = "security/xacml/test" + num + "/request.xml";
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      URL url = tcl.getResource(p1);
      assertNotNull("request file " + p1 + " null", url);
      return url.getPath();
   }

   /**
    * Get the String that represents the file
    * for the Request File  
    * @return
    */
   private String getResponseFile(int num) throws Exception
   {
      String p1 = "security/xacml/test" + num + "/response.xml";
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      URL url = tcl.getResource(p1);
      assertNotNull("response file " + p1 + " != null", url);
      return url.getPath();
   }

   /**
    * Get the ResponseCtx that represents a Syntax Error
    * @return
    */
   private ResponseCtx getSyntaxErrorResponseCtx()
   {
      ArrayList code = new ArrayList();
      code.add(Status.STATUS_SYNTAX_ERROR);
      Status status = new Status(code);

      return new ResponseCtx(new Result(Result.DECISION_INDETERMINATE, status));
   }
}
