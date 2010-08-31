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
package org.jboss.test.security.sunxacml.conformance;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.test.security.sunxacml.conformance.support.ConformanceTestPolicyFinderModule;
import org.jboss.test.security.sunxacml.conformance.support.TestAttributeFinderModule;
import org.jboss.test.security.sunxacml.conformance.support.TestPDP;
import org.jboss.test.security.sunxacml.conformance.support.TestPolicyFinderModule;

/**
 * Oasis XACML Conformance Tests
 * NOTE: The conformance tests contains tests have errors in the policy or request file.
 * In those cases, the PDP behavior can be one of ignoring the test
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Mar 24, 2009
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class ConformanceUnitTestCase extends TestCase
{
   String mandatoryBase = "src/test/resources/conformance/mandatory/";
   
   @SuppressWarnings("unused")
   public void testMandatoryConformance_AttributeReferences_01_through_21() throws Exception
   {  
      TestPDP pdp = null;
      for(int i =1; i<=21; i++)
      {
         System.out.println("Checking AttributeReferences_conformance:" + i);
         
         if(i == 4 || i == 5 || i == 12) //policy or request has an error
         {
            System.out.println("Ignoring AttributeReferences_conformance:" + i);
            continue;
         }
         
         String fileName = null;
         
         if(i < 10)
            fileName = mandatoryBase + "IIA00" + i + "Policy.xml"; 
         else
            fileName = mandatoryBase + "IIA0" + i + "Policy.xml";
         String[] policies = new String[] {fileName};
         pdp = new TestPDP(policies);  
         
         if(i == 2)
            pdp.addAttributeFinderModule(new TestAttributeFinderModule());
         
         pdp.createInternalPDP();
         
         
         String requestFile = null;
         if(i < 10)
            requestFile = mandatoryBase + "IIA00" + i + "Request.xml";
         else
            requestFile = mandatoryBase + "IIA0" + i + "Request.xml";
         ResponseCtx actualResponse = pdp.evaluate(requestFile); 
         assertNotNull("Response for" + i,actualResponse);
         
         String responseFile = null;
         if(i < 10)
            responseFile = mandatoryBase + "IIA00" + i + "Response.xml";
         else
            responseFile = mandatoryBase + "IIA0" + i + "Response.xml";
         InputStream responseStream = new FileInputStream(responseFile);
         if(responseStream  == null)
            throw new IllegalStateException("responseStream for IIA00"+ i + " is null");
         ResponseCtx expectedResponse = ResponseCtx.getInstance(responseStream);
          
         Result actualResult = (Result) actualResponse.getResults().iterator().next();
         Result expectedResult = (Result) expectedResponse.getResults().iterator().next();
         assertEquals("IIA00"+i, expectedResult.getDecision(),actualResult.getDecision());  
      }
   }
   
   @SuppressWarnings("unused")
   public void testMandatoryConformance_TargetMatching_1_through_53() throws Exception
   { 
      TestPDP pdp = null;
      for(int i =1; i<=53; i++)
      {
         System.out.println("Checking TargetMatching_conformance:" + i);
         String fileName = null;
         if(i < 10)
            fileName = mandatoryBase + "IIB00" + i + "Policy.xml";
         else
            fileName = mandatoryBase + "IIB0" + i + "Policy.xml";
         
         String[] policies = new String[] {fileName};
         pdp = new TestPDP(policies);  
         pdp.createInternalPDP(); 
         
         String requestFile = null;
         if(i < 10)
            requestFile = mandatoryBase + "IIB00" + i + "Request.xml";
         else
            requestFile = mandatoryBase + "IIB0" + i + "Request.xml";
         ResponseCtx actualResponse = pdp.evaluate(requestFile); 
         assertNotNull("Response for" + i,actualResponse);
         
         String responseFile = null;
         if(i < 10)
            responseFile = mandatoryBase + "IIB00" + i + "Response.xml";
         else
            responseFile = mandatoryBase + "IIB0" + i + "Response.xml";
         
         InputStream responseStream = new FileInputStream(responseFile);
         if(responseStream  == null)
            throw new IllegalStateException("responseStream for IIB0"+ i + " is null");
         ResponseCtx expectedResponse = ResponseCtx.getInstance(responseStream);

         Result actualResult = (Result) actualResponse.getResults().iterator().next();
         Result expectedResult = (Result) expectedResponse.getResults().iterator().next();
         assertEquals("IIB0"+i, expectedResult.getDecision(),actualResult.getDecision()); 
      }
   }
   
   @SuppressWarnings("unused")
   public void testMandatoryConformance_FunctionEvaluation_1_through_232() throws Exception
   { 
      TestPDP pdp = null;
      for(int i =1; i<=232; i++)
      {
         System.out.println("Checking FunctionEvaluation_conformance:" + i);
         if(i == 3 || i == 14 || i == 12) //Policy/request errors
         {
            System.out.println("Ignoring FunctionEvaluation_conformance:" + i);
            continue;
         }
         
         if(i == 23 || i == 54 || i == 55 || i == 88 || i == 89 ||
               i == 92 || i == 93 || i == 98 || i == 99) //Test is not present
            continue;
         
         String fileName = null;
         
         if(i < 10)
            fileName = mandatoryBase + "IIC00" + i + "Policy.xml";
         else if( i < 100)
            fileName = mandatoryBase + "IIC0" + i + "Policy.xml";
         else 
            fileName = mandatoryBase + "IIC" + i + "Policy.xml";
         
         String[] policies = new String[] {fileName};
         pdp = new TestPDP(policies);  
         pdp.createInternalPDP(); 
         
         
         String requestFile = null;
         if(i < 10)
            requestFile = mandatoryBase + "IIC00" + i + "Request.xml";
         else if(i < 100)
            requestFile = mandatoryBase + "IIC0" + i + "Request.xml";
         else
            requestFile = mandatoryBase + "IIC" + i + "Request.xml";
         
         ResponseCtx actualResponse = pdp.evaluate(requestFile); 
         assertNotNull("Response for" + i,actualResponse);
         
         String responseFile = null;
         if(i < 10)
            responseFile = mandatoryBase + "IIC00" + i + "Response.xml";
         else if( i < 100)
            responseFile = mandatoryBase + "IIC0" + i + "Response.xml";
         else
            responseFile = mandatoryBase + "IIC" + i + "Response.xml";
         
         InputStream responseStream = new FileInputStream(responseFile);
         if(responseStream  == null)
            throw new IllegalStateException("responseStream for IIC0"+ i + " is null");
         ResponseCtx expectedResponse = ResponseCtx.getInstance(responseStream);

         Result actualResult = (Result) actualResponse.getResults().iterator().next();
         Result expectedResult = (Result) expectedResponse.getResults().iterator().next();
         assertEquals("IIC0"+i, expectedResult.getDecision(),actualResult.getDecision()); 
      }
   }
   
   @SuppressWarnings("unused")
   public void testMandatoryConformance_CombiningAlgorithms_1_through_30() throws Exception
   { 
      TestPDP pdp = null;
      for(int i =1; i<=30; i++)
      {
         System.out.println("Checking CombiningAlgorithms_conformance:" + i);
         
         if(i == 29 || i == 30)
         {
            System.out.println("Ignoring CombiningAlgorithms_conformance:" + i);
            continue;
         }
         String fileName = null;
         if(i < 10)
            fileName = mandatoryBase + "IID00" + i + "Policy.xml";
         else
            fileName = mandatoryBase + "IID0" + i + "Policy.xml";
         
         String[] policies = new String[] {fileName};
         pdp = new TestPDP(policies);  
         pdp.createInternalPDP(); 
         
         String requestFile = null;
         if(i < 10)
            requestFile = mandatoryBase + "IID00" + i + "Request.xml";
         else
            requestFile = mandatoryBase + "IID0" + i + "Request.xml";
         ResponseCtx actualResponse = pdp.evaluate(requestFile); 
         assertNotNull("Response for" + i,actualResponse);
         
         String responseFile = null;
         if(i < 10)
            responseFile = mandatoryBase + "IID00" + i + "Response.xml";
         else
            responseFile = mandatoryBase + "IID0" + i + "Response.xml";
         
         InputStream responseStream = new FileInputStream(responseFile);
         if(responseStream  == null)
            throw new IllegalStateException("responseStream for IID0"+ i + " is null");
         ResponseCtx expectedResponse = ResponseCtx.getInstance(responseStream);

         Result actualResult = (Result) actualResponse.getResults().iterator().next();
         Result expectedResult = (Result) expectedResponse.getResults().iterator().next();
         assertEquals("IID0"+i, expectedResult.getDecision(),actualResult.getDecision()); 
      }
   }
   
   @SuppressWarnings("unused")
   public void testMandatoryConformance_Schema_1_through_3() throws Exception
   { 
      TestPDP pdp = null;
      for(int i =1; i<=3; i++)
      {
         System.out.println("Checking Schema_conformance:" + i);
          
         String fileName = null;
         if(i < 10)
            fileName = mandatoryBase + "IIE00" + i + "Policy.xml"; 
         
         String[] policies = new String[] {fileName};
         pdp = new TestPDP(policies);   
         pdp.addPolicyFinderModule(createTestPolicyFinderModule(i));
         pdp.createInternalPDP(); 
         
         String requestFile = null;
         if(i < 10)
            requestFile = mandatoryBase + "IIE00" + i + "Request.xml"; 
         ResponseCtx actualResponse = pdp.evaluate(requestFile); 
         assertNotNull("Response for" + i,actualResponse);
         
         String responseFile = null;
         if(i < 10)
            responseFile = mandatoryBase + "IIE00" + i + "Response.xml"; 
         
         InputStream responseStream = new FileInputStream(responseFile);
         if(responseStream  == null)
            throw new IllegalStateException("responseStream for IIE0"+ i + " is null");
         ResponseCtx expectedResponse = ResponseCtx.getInstance(responseStream);

         Result actualResult = (Result) actualResponse.getResults().iterator().next();
         Result expectedResult = (Result) expectedResponse.getResults().iterator().next();
         assertEquals("IIE0"+i, expectedResult.getDecision(),actualResult.getDecision()); 
      }
   }
    
   private PolicyFinderModule createTestPolicyFinderModule(int i) throws Exception
   {
      TestPolicyFinderModule tpfm = new ConformanceTestPolicyFinderModule();
      
      String policyRefString = "urn:oasis:names:tc:xacml:1.0:conformance-test:IIE00"+i+":policy1"; 
      URI policyRef = new URI(policyRefString); 
      Map policyRefs = new HashMap();
      policyRefs.put(policyRef.toString(), mandatoryBase + "IIE00" + i + "PolicyId1.xml");
      tpfm.setPolicyRefs(policyRefs, policyRef.toString());
      
      URI policySetRef = new URI("urn:oasis:names:tc:xacml:1.0:conformance-test:IIE00"+i+":policyset1");
      Map policySetRefs = new HashMap();
      policySetRefs.put(policySetRef.toString(), mandatoryBase + "IIE00" + i + "PolicySetId1.xml");  
      tpfm.setPolicySetRefs(policySetRefs, policySetRef.toString());
      return tpfm;
   } 
}