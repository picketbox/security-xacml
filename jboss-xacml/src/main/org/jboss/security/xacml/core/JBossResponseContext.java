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
package org.jboss.security.xacml.core;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.jboss.security.xacml.interfaces.ContextMapOp;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;

import com.sun.xacml.ctx.ResponseCtx;
import com.sun.xacml.ctx.Result;

//$Id$

/**
 *  Implementation of the ResponseContext interface
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class JBossResponseContext implements ResponseContext, ContextMapOp
{
   private int decision = XACMLConstants.DECISION_DENY;
   
   private Map<String,Object> map = new HashMap<String,Object>();

   /**
    * @see ContextMapOp#get(String)
    */
   public <T> T get(String key)
   {
      return (T) map.get(key);
   }
   
   /**
    * @see ContextMapOp#set(String, Object)
    */
   public <T> void set(String key, T obj)
   {
      map.put(key, obj);
   }

   /**
    * @see ResponseContext#getDecision()
    */
   public int getDecision()
   { 
      ResponseCtx response = (ResponseCtx) map.get(XACMLConstants.RESPONSE_CTX);
      if(response != null)
      {
         Set<Result> results = response.getResults();
         Result res = results.iterator().next();
         decision = res.getDecision();
      } 
      return decision;
         
   } 
}
