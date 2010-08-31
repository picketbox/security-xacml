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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.security.xacml.interfaces.AbstractLocator;
import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.sunxacml.ctx.RequestCtx;
import org.jboss.security.xacml.sunxacml.ctx.ResponseCtx;

/**
 * Base Class for Cache Locators
 * @author Anil.Saldhana@redhat.com
 * @since Aug 27, 2010
 */
public abstract class CacheLocator implements AbstractLocator
{ 
   protected List<Option> options = new ArrayList<Option>();
   
   protected Map<String,Object> optionMap = new HashMap<String, Object>();
   
   protected Map<String,Object> contextMap = new HashMap<String,Object>();
   
   @SuppressWarnings("unchecked")
   public <T> T get(String key)
   {
      return (T) contextMap.get(key);
   }

   public <T> void set(String key, T obj)
   {
       this.contextMap.put( key, obj );
   }

   public void setOptions(List<Option> options)
   {
       this.options.addAll( options );
       int len = options.size();
       for( int i = 0 ; i < len; i ++ )
       {
          Option option = options.get(i);
          optionMap.put( option.getName(),  option.getContent().iterator().next() );
       }
   } 
   
   public abstract ResponseCtx get( RequestCtx request );
}