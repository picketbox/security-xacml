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
package org.jboss.security.xacml.locators;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.security.xacml.interfaces.PolicyLocator;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.jaxb.Option;

//$Id$

/**
 *  
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public abstract class AbstractJBossPolicyLocator implements PolicyLocator
{
   protected List<Option> options = null; 
   protected Map<String,Object> map = new HashMap<String,Object>(); 
   protected Set<XACMLPolicy> policies;
   
   
   
   public void setOptions(List<Option> theoptions)
   { 
      this.options = theoptions;
   }

   public <T> T get(String key)
   { 
      return (T)map.get(key);
   }

   public <T> void set(String key, T obj)
   {
      map.put(key, obj); 
   }

   public abstract void setPolicies(Set<XACMLPolicy> policies); 
}
