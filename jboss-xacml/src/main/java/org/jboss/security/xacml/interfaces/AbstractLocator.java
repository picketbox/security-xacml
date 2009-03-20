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
package org.jboss.security.xacml.interfaces;

import java.util.List;

import org.jboss.security.xacml.jaxb.Option;

/**
 * Base interface for all locators
 * @author Anil.Saldhana@redhat.com
 * @since Mar 19, 2009
 */
public interface AbstractLocator extends ContextMapOp
{
   String IDENTIFIER_TAG = "identifier";
   
   String ATTRIBUTE_DESIGNATOR_SUPPORT_TAG = "attributeDesignatorSupport";
   
   String ATTRIBUTE_SELECTOR_SUPPORT_TAG = "attributeSelectorSupport";
   
   String ATTRIBUTE_SUPPORTED_ID_TAG = "attributeSupportedId";
   
   String ATTRIBUTE_DESIGNATOR_INTEGER_TAG = "attributeDesignatorInt";
   
   String RESOURCE_CHILD_SUPPORTED_TAG = "resourceChildSupport";
   
   String RESOURCE_DESCENDANT_SUPPORTED_TAG = "resourceDescendantSupport";
   
   /**
    * Set a list of options on the locator
    * @param options
    */
   void setOptions(List<Option> options); 
}