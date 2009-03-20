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
package org.jboss.security.xacml.locators;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.security.xacml.interfaces.AbstractLocator;
import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;

/**
 * An attribute finder module
 * 
 * <b>Usage:</b>
 * Remember, when a policy defines an attribute and the request does not contain
 * it, then the PDP will ask the AttributeLocator for a value.
 * 
 * The following methods need to be overridden in your attribute locators
 * @see AttributeFinderModule#findAttribute(String, org.w3c.dom.Node, URI, org.jboss.security.xacml.sunxacml.EvaluationCtx, String)
 * @see AttributeFinderModule#findAttribute(URI, URI, URI, URI, org.jboss.security.xacml.sunxacml.EvaluationCtx, int)
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Mar 19, 2009
 */
public class AttributeLocator extends AttributeFinderModule implements AbstractLocator
{
   private String identifier = null;
   
   private boolean attributeDesignatorSupported = true;
   
   private boolean attributeSelectorSupported = true;
   
   private Set<Integer> designatorTypes = new HashSet<Integer>();
   
   private Set<URI> ids = new HashSet<URI>();
   
   private List<Option> options = new ArrayList<Option>();
   
   private Map<String,Object> map = new HashMap<String,Object>();

   public void setOptions(List<Option> options)
   {
      this.options = options;
      try
      {
         processOptions();
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   @SuppressWarnings("unchecked")
   public <T> T get(String key)
   {
      return (T) this.map.get(key);   
   }

   public <T> void set(String key, T obj)
   {
      this.map.put(key, obj);     
   } 
   
   
   @Override
   public String getIdentifier()
   {
      if(identifier == null)
         return super.getIdentifier();
      return this.identifier;
   }

   @SuppressWarnings("unchecked")
   @Override
   public Set getSupportedDesignatorTypes()
   { 
      return this.designatorTypes;
   }

   @SuppressWarnings("unchecked")
   @Override
   public Set getSupportedIds()
   { 
      return this.ids;
   }

   @Override
   public boolean isDesignatorSupported()
   {
      return this.attributeDesignatorSupported;
   }

   @Override
   public boolean isSelectorSupported()
   {
      return this.attributeSelectorSupported;
   }

   private void processOptions() throws Exception
   {
      for(Option option:options)
      {
          String tag = option.getName();
          List<Object> values = option.getContent();
          
          String value = (String) values.get(0); 
          
          if(AbstractLocator.IDENTIFIER_TAG.equals(tag))
          {
             this.identifier = value;
          }
          else if(AbstractLocator.ATTRIBUTE_DESIGNATOR_SUPPORT_TAG.equals(tag))
          {
             this.attributeDesignatorSupported = Boolean.parseBoolean(value);
          }
          else if(AbstractLocator.ATTRIBUTE_SELECTOR_SUPPORT_TAG.equals(tag))
          {
             this.attributeSelectorSupported = Boolean.parseBoolean(value);
          }
          else if(AbstractLocator.ATTRIBUTE_SUPPORTED_ID_TAG.equals(tag))
          {
             this.ids.add(new URI(value)); 
          }
          else if(AbstractLocator.ATTRIBUTE_DESIGNATOR_INTEGER_TAG.equals(tag))
          {
             this.designatorTypes.add(Integer.parseInt(value)); 
          }
      }
   } 
}