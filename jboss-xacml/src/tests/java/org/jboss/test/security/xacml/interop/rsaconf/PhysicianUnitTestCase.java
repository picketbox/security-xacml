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
package org.jboss.test.security.xacml.interop.rsaconf;

import java.io.InputStream;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;

import junit.framework.TestCase;
 
/**
 *  Physician Unit Test Case 
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 25, 2008 
 *  @version $Revision$
 */
public class PhysicianUnitTestCase extends TestCase
{
   public void testRequest01_01() throws Exception
   {
      /**
      <!-- **************************************************************** -->
      <!-- Test case 1-01: Should be Perm: Dr A has all reqd perms          -->
      <!-- **************************************************************** -->
      **/
      validateCase("XacmlRequest-01-01.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testRequest01_02() throws Exception
   {
      /**
         <!-- **************************************************************** -->
         <!-- Test case 1-02: Should be Deny: Dr A missing 2 reqd perms        -->
         <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-01-02.xml", XACMLConstants.DECISION_DENY); 
   }
   
   public void testRequest01_03() throws Exception
   {
      /**
         <!-- **************************************************************** -->
         <!-- Test case 1-03: Should be Perm: Dr A has all reqd perms +2 extra -->
         <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-01-03.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testRequest01_04() throws Exception
   {
      /**
          <!-- **************************************************************** -->
          <!-- Test case 1-04: Should be Deny: Dr A has no facility             -->
          <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-01-04.xml", XACMLConstants.DECISION_DENY); 
   }
   
   public void testRequest02_01() throws Exception
   {
      /**
        <!-- **************************************************************** -->
        <!-- Test case 2-01: Should be Deny: provides role but needs perms    -->
        <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-02-01.xml", XACMLConstants.DECISION_DENY); 
   }
   
   public void testRequest02_02() throws Exception
   {
      /**
       <!-- **************************************************************** -->
       <!-- Test case 2-02: Should be Deny: Dr A is on dissented list        -->
       <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-02-02.xml", XACMLConstants.DECISION_DENY);  
   }

   public void testRequest02_03() throws Exception
   {
      /**
        <!-- **************************************************************** -->
        <!-- Test case 2-03: Should be Perm: Dr A is not on dissented list    -->
        <!-- **************************************************************** --> 
       */
      validateCase("XacmlRequest-02-03.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testRequest02_04() throws Exception
   {
      /**
      <!-- **************************************************************** -->
      <!-- Test case 2-04: Should be Deny: Dr A is on dissented multi-list  -->
      <!-- **************************************************************** -->
      **/
      validateCase("XacmlRequest-02-04.xml", XACMLConstants.DECISION_DENY); 
   }
  
   public void testRequest03_01() throws Exception
   {
      /**
      <!-- **************************************************************** -->
      <!-- Test case 3-01: Should be Deny: signed = Fals, Dr. A not author  -->
      <!-- **************************************************************** -->
      */
      validateCase("XacmlRequest-03-01.xml", XACMLConstants.DECISION_DENY);  
   }
   
   public void testRequest03_02() throws Exception
   {
      /**
        <!-- **************************************************************** -->
        <!-- Test case 3-02: Should be Permit: sign = True, Dr. A not author  -->
        <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-03-02.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testRequest03_03() throws Exception
   {
      /**
       * 
      !-- **************************************************************** -->
      <!-- Test case 3-03: Should be Perm: signed = Fals, Dr. A is author   -->
      <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-03-03.xml", XACMLConstants.DECISION_PERMIT);  
   }
   
   public void testRequest04_01() throws Exception
   {
      /**
      <!-- **************************************************************** -->
      <!-- Test case 4-01: Should be Perm + Obl: Dr A has emergency perm   -->
      <!-- **************************************************************** -->
      */
      validateCase("XacmlRequest-04-01.xml", XACMLConstants.DECISION_PERMIT);  
   }
   
   public void testRequest04_02() throws Exception
   {
      /**
        <!-- **************************************************************** -->
        <!-- Test case 04-02: Should be Perm + Obl: Dr A has emergency perm  -->
        <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-04-02.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testRequest04_03() throws Exception
   {
      /**
       * 
      !-- **************************************************************** -->
      <!-- Test case 4-03: Should be Deny+Obl: DrA has pea-001 but UBA set   -->
      <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-04-03.xml", XACMLConstants.DECISION_DENY);  
   }
   
   public void testRequest05_01() throws Exception
   {
      /**
       * **************************************************************** -->
       <!-- Test case 5-01: Should be Perm + Obl: Dr A is on dissented list  -->
       <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-05-01.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testRequest05_02() throws Exception
   {
      /**
       *  <!-- **************************************************************** -->
          <!-- Test case 5-02: Should be Perm: no obl; Dr A not on dis-list     -->
          <!-- **************************************************************** -->
       */
      validateCase("XacmlRequest-05-02.xml", XACMLConstants.DECISION_PERMIT); 
   } 
  
   public void testPatientSearch() throws Exception
   {
      validateCase("patient_search.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testEmergencyAccess() throws Exception
   {
      /**
       * The request contains the “pea-001” attribute, which, combined with the 
       * absence of the “env:locality” turns on emergency override.
       * If you remove the “pea” from the request, it should turn into a “deny”. 
       */
      validateCase("emergency_access.xml", XACMLConstants.DECISION_PERMIT); 
   }
   
   public void testEmergencyAccessDeny() throws Exception
   {
      /**
       * The request contains the “pea-001” attribute, which, combined with the 
       * absence of the “env:locality” turns on emergency override.
       * If you remove the “pea” from the request, it should turn into a “deny”. 
       */
      validateCase("emergency_access_deny.xml", XACMLConstants.DECISION_DENY); 
   }
   
   private PolicyDecisionPoint getPDP()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("test/config/rsaConferencePolicySetConfig.xml");
      assertNotNull("InputStream != null", is);

      return new JBossPDP(is);
   }
   
   private void validateCase(String loc, int decisionval) throws Exception
   {
      loc = "test/requests/interop/rsaconf08/" + loc;
      
      int decision = XACMLTestUtil.getDecision(getPDP(), loc);   
      switch(decisionval)
      {
         case XACMLConstants.DECISION_PERMIT: 
            assertEquals("PERMIT?", XACMLConstants.DECISION_PERMIT,decision);
            break;
         case XACMLConstants.DECISION_DENY:
            assertEquals("DENY?", XACMLConstants.DECISION_DENY,decision);
            break;
         default: fail("wrong value");
      }  
   }
   
}