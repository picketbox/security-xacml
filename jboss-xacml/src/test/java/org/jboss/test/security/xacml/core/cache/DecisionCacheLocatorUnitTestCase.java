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
package org.jboss.test.security.xacml.core.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.locators.cache.DecisionCacheLocator.DecisionCacheLocatorRequest;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.Subject;
import org.jboss.test.security.xacml.factories.util.XACMLTestUtil;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 * @author Anil.Saldhana@redhat.com
 * @since Aug 30, 2010
 */
public class DecisionCacheLocatorUnitTestCase
{ 
   private static String CONFIG_FILE_NO_CACHING = "test/config/interopPolicySetConfig.xml";
   private static String CONFIG_FILE_CACHING = "test/config/cache/DecisionCacheLocatorConfig.xml";
   private static String CONFIG_FILE_CACHING_WITH_SPEED = "test/config/cache/DecisionCacheLocatorConfig_WithSpeed.xml";

   private static PolicyDecisionPoint non_cached_pdp = null;
   private static PolicyDecisionPoint cached_pdp = null;
   private static PolicyDecisionPoint cached_with_speed_pdp = null;

   private static String REQUEST1 = "test/requests/interop/scenario2-testcase1-request.xml";
   private static String REQUEST2 = "test/requests/interop/scenario2-testcase2-request.xml";
   private static String REQUEST3 = "test/requests/interop/scenario2-testcase3-request.xml";
   private static String REQUEST4 = "test/requests/interop/scenario2-testcase4-request.xml";
   private static String REQUEST5 = "test/requests/interop/scenario2-testcase5-request.xml";
   private static String REQUEST6 = "test/requests/interop/scenario2-testcase6-request.xml";
   private static String REQUEST7 = "test/requests/interop/scenario2-testcase7-request.xml"; 

   @BeforeClass
   public static void init()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream( CONFIG_FILE_CACHING );
      assertNotNull( "InputStream != null", is );
      cached_pdp = new JBossPDP( is );
      assertNotNull("JBossPDP with caching is != null", cached_pdp);

      is =  tcl.getResourceAsStream( CONFIG_FILE_NO_CACHING );
      assertNotNull( "InputStream != null", is );
      non_cached_pdp = new JBossPDP( is );
      assertNotNull("JBossPDP is != null", non_cached_pdp);
      
      is =  tcl.getResourceAsStream( CONFIG_FILE_CACHING_WITH_SPEED );
      assertNotNull( "InputStream != null", is );
      cached_with_speed_pdp = new JBossPDP( is );
      assertNotNull("JBossPDP is != null", cached_with_speed_pdp);
   }

   @SuppressWarnings("rawtypes")
   @Test
   public void testCacheRequestGeneration() throws Exception
   {
      RequestContext request = XACMLTestUtil.getRequest( "test/requests/env/DateTimeRequest.xml" );
      RequestCtx xacmlRequest = (RequestCtx) request.get( XACMLConstants.REQUEST_CTX );

      List subjectSet = xacmlRequest.getSubjectsAsList();
      assertEquals( "Number of subjects is 1", 1, subjectSet.size() );

      Subject xacmlSubject = (Subject) subjectSet.iterator().next();

      assertEquals( "Number of subject attributes is 6", 6, xacmlSubject.getAttributesAsList().size() );

      assertEquals( "Number of resource attributes is 7", 7, xacmlRequest.getResourceAsList().size() );
      assertEquals( "Number of action attributes is 1", 1, xacmlRequest.getActionAsList().size() );
      assertEquals( "Number of Env attributes is 1", 1, xacmlRequest.getEnvironmentAttributesAsList().size() ); 

      //Let us reduce the env
      List<String> ignoreEnv = new ArrayList<String>();
      ignoreEnv.add( "urn:oasis:names:tc:xacml:1.0:environment:current-time" ); 

      RequestCtx cachedRequest = DecisionCacheLocatorRequest.from( xacmlRequest, null, null, null, ignoreEnv ); 
      assertNotNull( "Is CachedRequest null?", cachedRequest ); 

      //Ensure that the environment attributes are empty
      assertEquals( "The Environment should be empty", 0, cachedRequest.getEnvironmentAttributesAsList().size() );

      //Let us reduce the subjects
      List<String> ignoreSubject = new ArrayList<String>();
      ignoreSubject.add( "urn:oasis:names:tc:xacml:1.0:subject:subject-id" );

      cachedRequest = DecisionCacheLocatorRequest.from( xacmlRequest, ignoreSubject, null, null, null ); 
      assertNotNull( "Is CachedRequest null?", cachedRequest ); 

      Subject cachedSubject = (Subject) cachedRequest.getSubjectsAsList().iterator().next();
      assertEquals( "Number of subject attributes is 5", 5, cachedSubject.getAttributesAsList().size() );

      //Let us reduce the resource
      List<String> ignoreResource = new ArrayList<String>();
      ignoreResource.add( "urn:xacml:2.0:interop:example:resource:trade-limit" );

      cachedRequest = DecisionCacheLocatorRequest.from( xacmlRequest, null, ignoreResource, null, null ); 
      assertNotNull( "Is CachedRequest null?", cachedRequest ); 

      assertEquals( "Number of resource attributes is 6", 6, cachedRequest.getResourceAsList().size() );

      //Let us reduce the action
      List<String> ignoreAction = new ArrayList<String>();
      ignoreAction.add( "urn:oasis:names:tc:xacml:1.0:action:action-id" ); 

      cachedRequest = DecisionCacheLocatorRequest.from( xacmlRequest, null, null, ignoreAction, null ); 
      assertNotNull( "Is CachedRequest null?", cachedRequest ); 

      assertEquals( "Number of action attributes is 0", 0, cachedRequest.getActionAsList().size() ); 
   }

   @Test
   public void testCache() throws Exception
   { 
      System.out.println( "We are going to run a short performance test that will take under 1 min " );
      int len = 2;

      long start = System.currentTimeMillis(); 
      for( int i = 0 ; i < len; i++ )
      {
         runTests( non_cached_pdp ); 
      }
      long elapsedTimeMillis = System.currentTimeMillis() - start; 
      System.out.println("Without Decision Caching, time spent for " + len  
            + " iterations in = " + elapsedTimeMillis + " ms or " + elapsedTimeMillis/1000F + " secs");

      
      
      start = System.currentTimeMillis(); 
      for( int i = 0 ; i < len; i++ )
      { 
         runTests( cached_pdp ); 
      } 
      elapsedTimeMillis = System.currentTimeMillis() - start; 
      System.out.println("With Decision Caching, time spent for " + len  
            + " iterations in = " + elapsedTimeMillis + " ms or " + elapsedTimeMillis/1000F + " secs"); 
      
      start = System.currentTimeMillis(); 
      for( int i = 0 ; i < len; i++ )
      { 
         runTests( cached_with_speed_pdp ); 
      } 
      elapsedTimeMillis = System.currentTimeMillis() - start; 
      System.out.println("With Decision Caching (Enhanced Speed), time spent for " + len  
            + " iterations in = " + elapsedTimeMillis + " ms or " + elapsedTimeMillis/1000F + " secs");
   }

   private void runTests( PolicyDecisionPoint pdp) throws Exception
   {
      TestCase.assertEquals("Case 1 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision (pdp,REQUEST1 ));
      TestCase.assertEquals("Case 2 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp, REQUEST2 ));
      TestCase.assertEquals("Case 3 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp, REQUEST3 ));
      TestCase.assertEquals("Case 4 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp, REQUEST4 ));
      TestCase.assertEquals("Case 5 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp, REQUEST5 ));
      TestCase.assertEquals("Case 6 should be deny", XACMLConstants.DECISION_DENY, XACMLTestUtil.getDecision(pdp, REQUEST6 ));
      TestCase.assertEquals("Case 7 should be permit", XACMLConstants.DECISION_PERMIT, XACMLTestUtil.getDecision(pdp, REQUEST7 ));
   }
}