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
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.security.xacml.interfaces.AbstractLocator;
import org.jboss.security.xacml.jaxb.Option;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.cond.EvaluationResult;
import org.jboss.security.xacml.sunxacml.finder.AttributeFinderModule;

/**
 * An attribute finder module
 * 
 * <b>Usage:</b>
 * Remember, when a policy defines an attribute and the request does not contain
 * it, then the PDP will ask the AttributeLocator for a value.
 *  
 * The following method needs to be overridden in your attribute locator
 * @see AttributeFinderModule#findAttribute(URI, URI, URI, URI, org.jboss.security.xacml.sunxacml.EvaluationCtx, int)
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Mar 19, 2009
 */
public class AttributeLocator extends AttributeFinderModule implements AbstractLocator
{
   protected String identifier = null;
   
   protected boolean attributeDesignatorSupported = true;
   
   protected boolean attributeSelectorSupported = true;
   
   protected Set<Integer> designatorTypes = new HashSet<Integer>();
   
   protected Set<URI> ids = new HashSet<URI>();
   
   protected List<Option> options = new ArrayList<Option>();
   
   protected Map<String,Object> map = new HashMap<String,Object>();

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

   @SuppressWarnings("rawtypes")
   @Override
   public Set getSupportedDesignatorTypes()
   { 
      return this.designatorTypes;
   }

   @SuppressWarnings("rawtypes")
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
          
          this.usePassedOption(tag, value); 
      }
   } 
   
   /**
    * <p>
    * An opportunity for sub-classes to process the passed option tag and value
    * </p>
    * <p>
    * <b>NOTE:</b> Subclasses should override this method and allow super class processing
    * before their own processing in the method via the <i>super.usePassedOption()</i> call.
    * </p>
    * @param optionTag
    * @param optionValue
    */
   protected void usePassedOption(String optionTag, String optionValue) 
   {
      if(AbstractLocator.IDENTIFIER_TAG.equals(optionTag))
      {
         this.identifier = optionValue;
      }
      else if(AbstractLocator.ATTRIBUTE_DESIGNATOR_SUPPORT_TAG.equals(optionTag))
      {
         this.attributeDesignatorSupported = Boolean.parseBoolean(optionValue);
      }
      else if(AbstractLocator.ATTRIBUTE_SELECTOR_SUPPORT_TAG.equals(optionTag))
      {
         this.attributeSelectorSupported = Boolean.parseBoolean(optionValue);
      }
      else if(AbstractLocator.ATTRIBUTE_SUPPORTED_ID_TAG.equals(optionTag))
      {
         try
         {
            this.ids.add(new URI(optionValue));
         }
         catch (URISyntaxException e)
         {
            throw new RuntimeException("Unable to create URI:", e);
         } 
      }
      else if(AbstractLocator.ATTRIBUTE_DESIGNATOR_INTEGER_TAG.equals(optionTag))
      {
         this.designatorTypes.add(Integer.parseInt(optionValue)); 
      } 
   }
   
   /**
    * Given an <i>option tag</i>, get the <i>option value</i>
    * @param optionTag
    * @return value of the option
    */
   protected String getOptionValue(String optionTag)
   {
      int index = options.indexOf(optionTag);
      if(index > -1)
      {
         Option option = options.get(index);
         if(option != null)
            return (String) option.getContent().get(0);
      }
      return null;
   }
   
   /**
    * Given a <code>EvaluationResult</code>, return the attribute value contained
    * @param evalResult
    * @param attributeType
    * @return attribute value such as String, Integer etc.
    */
   protected Object getAttributeValue(EvaluationResult evalResult, URI attributeType)
   {
      if(evalResult != null)
      {
         AttributeValue attr = evalResult.getAttributeValue(); 
         return attr.getValue();
      }
      return null;
   } 
}