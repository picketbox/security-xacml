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

import org.jboss.security.xacml.core.ext.ExtendedAttributeFactoryProxy;
import org.jboss.security.xacml.core.ext.MultiValueAttributeProxy;
import org.jboss.security.xacml.core.ext.SingleValueAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.AttributeFactory;

/**
 *  Installs some custom PDP Configuration
 *  such as custom attributes
 *  
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 28, 2008 
 *  @version $Revision$
 */
public class PDPConfiguration
{
   static
   {
      AttributeFactory.setDefaultFactory(new ExtendedAttributeFactoryProxy());
   }

   public static void installSingleValueAttribute(String type)
   {
      AttributeFactory factory = AttributeFactory.getInstance();
      factory.addDatatype(type, new SingleValueAttributeProxy(type));

   }

   public static void installMultiValueAttribute(String type)
   {
      AttributeFactory factory = AttributeFactory.getInstance();
      factory.addDatatype(type, new MultiValueAttributeProxy(type));

   }
}