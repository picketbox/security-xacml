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
package org.jboss.security.xacml.locators.cache;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.StringTokenizer;
import java.util.WeakHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jboss.security.xacml.sunxacml.ctx.Attribute;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;
import org.jboss.security.xacml.sunxacml.ctx.Subject;


/**
 * A Cache that stores decisions made on requests.
 * 
 * NOTE: Configure this if you know that your requests are going to closely match each other.
 * If the requests are going to be independent, then the cache will just grow. Since the cache
 * implementation uses a {@code java.util.WeakHashMap}, the cache is going to be JDK controlled
 * under the Garbage Collector.
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Aug 27, 2010
 */
public class DecisionCacheLocator extends CacheLocator
{
   private static Logger log = Logger.getLogger( DecisionCacheLocator.class.getCanonicalName() );
   
   protected WeakHashMap<RequestCtx, ResponseCtx> correctnessDecisionMap = null;
   
   protected LinkedHashMap< RequestCtx, ResponseCtx> speedDecisionMap = null; 
   
   public static final String IGNORE_SUBJECT_ID = "ignoreSubjectID";
   public static final String IGNORE_RESOURCE_ID = "ignoreResourceID";
   public static final String IGNORE_ACTION_ID = "ignoreActionID";
   public static final String IGNORE_ENVIRONMENT_ID = "ignoreEnvironmentID";
   
   public static final String ENHANCE_SPEED = "enhanceSpeed";
   
   public static final String INITIAL_CAPACITY = "initialCapacity";
   public static final String LOAD_FACTOR = "loadFactor";

   /**
    * Add a {@code RequestCtx} and a {@code ResponseCtx} to the cache
    * @param request
    * @param response
    */
   public void add( RequestCtx request, ResponseCtx response )
   {
      RequestCtx cacheRequest = preprocessRequest( request );
      
      if( needCorrectness() )
      {   
         this.validateCorrectnessMap(); 
         this.correctnessDecisionMap.put( cacheRequest, response ); 
      }
      else
      {
         this.validateSpeedMap();
         this.speedDecisionMap.put( cacheRequest, response );
      }
   }
   
   /**
    * Get a {@code ResponseCtx} response that we have cached
    * for a {@code RequestCtx} request.
    * @return response object if cached else null
    */
   public ResponseCtx get( RequestCtx request )
   {
      RequestCtx cacheRequest = preprocessRequest( request );
      
      ResponseCtx response = null;
      
      int correctnessSize = correctnessDecisionMap != null ? correctnessDecisionMap.size() : 0;
      int speedSize = speedDecisionMap != null ? speedDecisionMap.size() : 0;
      
      
      if( needCorrectness() )
      {   
         this.validateCorrectnessMap();
         response = this.correctnessDecisionMap.get( cacheRequest );
      }
      else
      {
         this.validateSpeedMap(); 
         response = this.speedDecisionMap.get( cacheRequest );
      }
      
      if( response == null )
      {
         
         log.log( Level.FINEST, "Cache Miss with " + toString() + " correctness size=" + correctnessSize
                      + " speed size=" + speedSize ); 
      } 
      
      return response;
   } 

   /**
    * Specialized version of {@code RequestCtx} that is suited to be cached
    * @author anil 
    */
   public static class DecisionCacheLocatorRequest extends RequestCtx
   {  
      @SuppressWarnings("rawtypes")
      public DecisionCacheLocatorRequest(List subjects, List resource, List action, List environment)
      {
         super(subjects, resource, action, environment); 
      } 
      
      @SuppressWarnings("rawtypes")
      public static RequestCtx from( RequestCtx request, List<String> ignoreSubjectIDs,
            List<String> ignoreResourceIDs, List<String> ignoreActionIDs, List<String> ignoreEnvIDs )
      {   
         List requestSubject = request.getSubjectsAsList();
         if( ignoreSubjectIDs != null )
            requestSubject = processSubject( requestSubject, ignoreSubjectIDs );
         
         List requestResource = request.getResourceAsList();
         if( ignoreResourceIDs != null )
            requestResource = processAttributes( requestResource, ignoreResourceIDs );
         
         List requestAction = request.getActionAsList();
         if( ignoreActionIDs != null )
            requestAction = processAttributes(requestAction, ignoreActionIDs); 
         
         List requestEnvironment = request.getEnvironmentAttributesAsList();
         
         if( ignoreEnvIDs != null )
            requestEnvironment = processAttributes( requestEnvironment, ignoreEnvIDs );
          
         RequestCtx myRequest = new DecisionCacheLocatorRequest( requestSubject, requestResource, requestAction, requestEnvironment);
         return myRequest;
      }
       
      @SuppressWarnings({"rawtypes", "unchecked"})
      private static List processSubject( List origSet, List<String> ignoreIDs )
      {
         List resultSet = new ArrayList();
         
         Iterator envIter = origSet != null ? origSet.iterator() : null;
         
         while( envIter != null && envIter.hasNext() )
         {
            Subject subject = (Subject) envIter.next(); 
            List attributes = subject.getAttributesAsList();
            
            attributes = processAttributes(attributes, ignoreIDs);
            
            Subject newSubject = new Subject(attributes);
            resultSet.add(newSubject);
         }
         return resultSet;
      }
      
      @SuppressWarnings({"rawtypes", "unchecked"})
      private static List processAttributes( List origSet, List<String> ignoreIDs )
      {
         List resultSet = new ArrayList();
         
         Iterator envIter = origSet != null ? origSet.iterator() : null;
         
         while( envIter != null && envIter.hasNext() )
         {
            Attribute iterObject = (Attribute) envIter.next();
            
            String id = iterObject.getId().toASCIIString();
            
            if( ignoreIDs.contains( id ))
               continue;
            
            resultSet.add( iterObject );   
         }
         return resultSet;
      } 
      
   }
   
   /**
    * Transform the XACML request into a request that we can place
    * in the cache, while considering any of the (subject, resource, action, environment)
    * attributes that need to be ignored
    * @param request
    * @return
    */
   private RequestCtx  preprocessRequest( RequestCtx request )
   {
      List<String> subjectID = new ArrayList<String>();
      List<String> resourceID = new ArrayList<String>();
      List<String> actionID = new ArrayList<String>();
      List<String> envID = new ArrayList<String>();
      
      String ignoreSubjectOption = (String) optionMap.get( IGNORE_SUBJECT_ID );
      String ignoreResourceOption = (String) optionMap.get( IGNORE_RESOURCE_ID );
      String ignoreActionOption = (String) optionMap.get( IGNORE_ACTION_ID );
      String ignoreEnvOption = (String) optionMap.get( IGNORE_ENVIRONMENT_ID );
      
      subjectID.addAll( getTokenList( ignoreSubjectOption ));
      resourceID.addAll( getTokenList( ignoreResourceOption ));
      actionID.addAll( getTokenList( ignoreActionOption ));
      envID.addAll( getTokenList( ignoreEnvOption ));
      
      return DecisionCacheLocatorRequest.from( request, 
            subjectID, resourceID, actionID, envID ); 
   }
   
   /**
    * Get a list of token from comma separated string
    * @param commaSeparatedListOfStrings
    * @return
    */
   private List<String> getTokenList( String commaSeparatedListOfStrings )
   {
      List<String> stringList = new ArrayList<String>();
      
      if( commaSeparatedListOfStrings != null )
      {  
         StringTokenizer st = new StringTokenizer(commaSeparatedListOfStrings, ",");
         
         while( st != null && st.hasMoreTokens() )
         {
            stringList.add( st.nextToken() ); 
         } 
      }
      return stringList;
   }
   
   /**
    * Determine whether we need correctness (WeakHashMap)  or Speed (LinkedHashMap)
    * @return
    */
   private boolean needCorrectness()
   {
      boolean correctness = false;
      String correct = (String) optionMap.get( ENHANCE_SPEED );
      if( correct != null && "false".equalsIgnoreCase( correct ))
         correctness = true;
       
      return correctness;
   }
   
   /**
    * Validate that the WeakHashMap is not null
    */
   private void validateCorrectnessMap()
   { 
      if( correctnessDecisionMap == null )
      { 
         int initialCapacity  = getInitialCapacity(); 
         float loadFactor = getLoadFactor();
         correctnessDecisionMap = new WeakHashMap<RequestCtx, ResponseCtx>( initialCapacity , loadFactor ); 
      }
   }
   
   /**
    * Validate that the LRU LinkedHashMap is not null
    */
   private void validateSpeedMap()
   {
      if( speedDecisionMap == null )
      {
         int initialCapacity  = getInitialCapacity(); 
         float loadFactor = getLoadFactor();
         
         speedDecisionMap = new LinkedHashMap<RequestCtx, ResponseCtx>( initialCapacity, loadFactor, true ); 
      } 
   }
   
   /**
    * Get the configured Initial Capacity
    * @return
    */
   private int getInitialCapacity()
   {
      int initialCapacity = 100;
      
      String initialCapacityStr = (String) optionMap.get( INITIAL_CAPACITY );
      if( initialCapacityStr != null && initialCapacityStr != "" )
      {
         initialCapacity = Integer.parseInt( initialCapacityStr );
      }
      return initialCapacity;
   }
   
   /**
    * Get the configured load factor
    * @return
    */
   private float getLoadFactor()
   {
      float loadFactor = 0.75F;
      String loadFactorStr = (String) optionMap.get( LOAD_FACTOR );
      if( loadFactorStr != null && loadFactorStr != "" )
      {
         loadFactor = Float.parseFloat( loadFactorStr );
      }
      return loadFactor; 
   }
}