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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.jboss.security.xacml.sunxacml.Indenter;
import org.jboss.security.xacml.sunxacml.Obligation;
import org.jboss.security.xacml.sunxacml.combine.PermitOverridesPolicyAlg;
import org.jboss.security.xacml.sunxacml.ctx.Attribute;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Result;
import org.jboss.security.xacml.sunxacml.ctx.Status;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.impl.CurrentEnvModule;
import org.jboss.security.xacml.sunxacml.finder.impl.SelectorModule;
import org.jboss.security.xacml.sunxacml.support.finder.StaticRefPolicyFinderModule;
import org.jboss.security.xacml.sunxacml.support.finder.URLPolicyFinderModule;
import org.jboss.test.security.test.xacml.modules.JBossStaticPolicyFinderModule;
import org.jboss.test.security.test.xacml.modules.TestRoleAttributeFinderModule;

//$Id: XACMLUtil.java 58115 2006-11-04 08:42:14Z scott.stark@jboss.org $

/**
 *  Some Util methods for the XACML Suite of tests
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 30, 2006 
 *  @version $Revision: 58115 $
 */
public class XACMLUtil
{ 
   //Validate that two PDP responses are the same semantically
   public static void assertEquals(ResponseCtx first, ResponseCtx second)
   throws Exception
   {
      assertResults(first.getResults(), second.getResults()); 
   }
   
   // Validate that two PDP response->results are the same semantically
   public static void assertResults(Set first, Set second) throws Exception
   {  
      if (first.size() != second.size())
         throw new Exception("Size of results mismatch");
      
      Iterator iter = first.iterator();
      
      // A set allows us to remove matching results individually
      HashSet set2 = new HashSet(second);
      
      // consider each Result in the first Response, and try to find an
      // equivalent one in the second Response
      while (iter.hasNext()) 
      {
         Result result1 = (Result)(iter.next());
         Iterator it2 = set2.iterator();
         boolean matched = false;
         
         // go through the second list, and see if there's a matching Result
         while (it2.hasNext() && (! matched)) 
         {
            Result result2 = (Result)(it2.next());
            if (result1.getDecision() != result2.getDecision())
               throw new Exception("decision in the result do not match");
            assertStringMatch(result1.getResource(), result2.getResource());
            assertStatus(result1.getStatus(), result2.getStatus());
            assertObligations(result1.getObligations(),
                  result2.getObligations()); 
            matched = true; 
         }
         
         // When matched, remove the result from the second set
         if (matched)
            it2.remove();
         else
            throw new Exception("result mismatch");
      } 
   }
   
   public static void assertStringMatch(String first, String second)
   throws Exception
   {
      Exception ex = new Exception(first + "!=" + second); 
      
      if (first == null && second != null)  
         throw ex;
      if(second != null && first.equals(second) == false)
         throw ex;  
   }
   
   // Validate that two PDP response ->Status  are the same semantically
   public static void assertStatus(Status first, Status second) 
   throws Exception
   {
      Exception ex = new Exception(first + "!=" + second); 
      Iterator it1 = first.getCode().iterator();
      Iterator it2 = second.getCode().iterator();
      
      // Same code appear in the status?
      while (it1.hasNext()) 
      { 
         if (! it2.hasNext())
            throw ex;
         String code = (String)(it1.next());
         
         // check that the specific code is the same at each step
         if (! (code).equals((String)(it2.next())))
            throw ex;
      }
      
      // if there's still more in the second list, then they're not equal
      if (it2.hasNext())
         throw ex; 
   }
   
   // Validate that two PDP response->Obligations are the same semantically
   public static void assertObligations(Set first, Set second)
   throws Exception
   {
      if (first.size() != first.size())
         throw new Exception("Obligations sets do not match in size");
      
      Iterator it1 = first.iterator();
      
      // Set for the second set of Obligations, so we can
      // remove the matching Obligation at each step
      HashSet set2 = new HashSet(second);
      
      // For each Obligation in the first set, and try to find an
      // equivalent one in the second set
      while (it1.hasNext()) 
      {
         Obligation o1 = (Obligation)(it1.next());
         Iterator it2 = set2.iterator();
         boolean matched = false;
         
         // go through the second set, and see if there's a matching
         // Obligation
         while (it2.hasNext() && (! matched)) 
         {
            Obligation o2 = (Obligation)(it2.next());
            
            // Match identifier and fulfillOn setting
            if ((o1.getId().equals(o2.getId())) &&
                  (o1.getFulfillOn() == o2.getFulfillOn())) 
            {
               // Match the assignments 
               List assignments1 = o1.getAssignments();
               List assignments2 = o2.getAssignments();
               
               if (assignments1.size() == assignments2.size()) 
               {
                  Iterator ait1 = assignments1.iterator();
                  Iterator ait2 = assignments2.iterator();
                  boolean assignmentsMatch = true;
                  
                  while (ait1.hasNext() && assignmentsMatch) 
                  {
                     Attribute attr1 = (Attribute)(ait1.next());
                     Attribute attr2 = (Attribute)(ait2.next());
                     
                     if ((! attr1.getId().equals(attr2.getId())) ||
                           (! attr1.getType().equals(attr2.getType())) ||
                           (! attr1.getValue().equals(attr2.getValue())))
                        assignmentsMatch = false;
                  }
                  
                  matched = assignmentsMatch;
               }
            }
         }
         
         // If matched, remove it from the set 
         if (matched)
            it2.remove();
         else
            throw new Exception("Obligations do not match");
      } 
   }
   
   /**
    * Get a prebuilt AttributeFinder
    * @return
    */
   public static AttributeFinder getAttributeFinder()
   {
      //Prefill the attribute finder with the Sun's impl of 
      //environment attribute module and the selector attribute module
      AttributeFinder attributeFinder = new AttributeFinder();
      List attributeModules = new ArrayList();
      attributeModules.add(new TestRoleAttributeFinderModule()); 
      attributeModules.add(new CurrentEnvModule());
      attributeModules.add(new SelectorModule());
      attributeFinder.setModules(attributeModules);
      return attributeFinder;
   } 
   
   /**
    * Get a Prebuilt PolicyFinder with the passed array of policy files
    * @param policyFiles
    * @return
    * @throws Exception
    */
   public static PolicyFinder getPolicyFinder(String[] policyFiles) throws Exception
   {
      List policyFileList = Arrays.asList(policyFiles);
      PolicyFinder policyFinder = new PolicyFinder();
      HashSet policyModules = new HashSet();
      policyModules.add(new JBossStaticPolicyFinderModule(PermitOverridesPolicyAlg.algId,
            policyFileList));
      policyModules.add(new StaticRefPolicyFinderModule(policyFileList));
      policyModules.add(new URLPolicyFinderModule());
      policyFinder.setModules(policyModules);
      return policyFinder;
   }
   
   /**
    * Log the PDP response to system out
    * @param response
    * @param flag true=response will be displayed false=no
    */
   public static void logResponseCtxToSystemOut(ResponseCtx response,
         boolean flag)
   {
      if(flag)
        response.encode(System.out, new Indenter());
   } 
   
   public static void logRequest(RequestCtx request) throws Exception
   {
      request.encode(System.out, new Indenter());
   }
}
