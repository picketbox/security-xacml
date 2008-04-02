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
package org.jboss.security.xacml.core.ext;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.UnknownIdentifierException;
import org.jboss.security.xacml.sunxacml.attr.AnyURIAttribute;
import org.jboss.security.xacml.sunxacml.attr.AttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.attr.Base64BinaryAttribute;
import org.jboss.security.xacml.sunxacml.attr.BaseAttributeFactory;
import org.jboss.security.xacml.sunxacml.attr.BooleanAttribute;
import org.jboss.security.xacml.sunxacml.attr.DNSNameAttribute;
import org.jboss.security.xacml.sunxacml.attr.DateAttribute;
import org.jboss.security.xacml.sunxacml.attr.DateTimeAttribute;
import org.jboss.security.xacml.sunxacml.attr.DayTimeDurationAttribute;
import org.jboss.security.xacml.sunxacml.attr.DoubleAttribute;
import org.jboss.security.xacml.sunxacml.attr.HexBinaryAttribute;
import org.jboss.security.xacml.sunxacml.attr.IPAddressAttribute;
import org.jboss.security.xacml.sunxacml.attr.IntegerAttribute;
import org.jboss.security.xacml.sunxacml.attr.RFC822NameAttribute;
import org.jboss.security.xacml.sunxacml.attr.StringAttribute;
import org.jboss.security.xacml.sunxacml.attr.TimeAttribute;
import org.jboss.security.xacml.sunxacml.attr.X500NameAttribute;
import org.jboss.security.xacml.sunxacml.attr.YearMonthDurationAttribute;
import org.jboss.security.xacml.sunxacml.attr.proxy.AnyURIAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.Base64BinaryAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.BooleanAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.DNSNameAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.DateAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.DateTimeAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.DayTimeDurationAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.DoubleAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.HexBinaryAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.IPAddressAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.IntegerAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.RFC822NameAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.StringAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.TimeAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.X500NameAttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.proxy.YearMonthDurationAttributeProxy;
import org.w3c.dom.Node;

/**
 *  Extendible Attribute factory
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 28, 2008 
 *  @version $Revision$
 */
public class ExtendedAttributeFactory extends BaseAttributeFactory
{

   private static ExtendedAttributeFactory instance = null;

   private static Map supportedDatatypes = new HashMap();

   private ExtendedAttributeFactory()
   {
      super(supportedDatatypes);

      // the 1.x datatypes
      supportedDatatypes.put(BooleanAttribute.identifier, new BooleanAttributeProxy());
      supportedDatatypes.put(StringAttribute.identifier, new StringAttributeProxy());
      supportedDatatypes.put(DateAttribute.identifier, new DateAttributeProxy());
      supportedDatatypes.put(TimeAttribute.identifier, new TimeAttributeProxy());
      supportedDatatypes.put(DateTimeAttribute.identifier, new DateTimeAttributeProxy());
      supportedDatatypes.put(DayTimeDurationAttribute.identifier, new DayTimeDurationAttributeProxy());
      supportedDatatypes.put(YearMonthDurationAttribute.identifier, new YearMonthDurationAttributeProxy());
      supportedDatatypes.put(DoubleAttribute.identifier, new DoubleAttributeProxy());
      supportedDatatypes.put(IntegerAttribute.identifier, new IntegerAttributeProxy());
      supportedDatatypes.put(AnyURIAttribute.identifier, new AnyURIAttributeProxy());
      supportedDatatypes.put(HexBinaryAttribute.identifier, new HexBinaryAttributeProxy());
      supportedDatatypes.put(Base64BinaryAttribute.identifier, new Base64BinaryAttributeProxy());
      supportedDatatypes.put(X500NameAttribute.identifier, new X500NameAttributeProxy());
      supportedDatatypes.put(RFC822NameAttribute.identifier, new RFC822NameAttributeProxy());

      // the 2.0 datatypes
      supportedDatatypes.put(DNSNameAttribute.identifier, new DNSNameAttributeProxy());
      supportedDatatypes.put(IPAddressAttribute.identifier, new IPAddressAttributeProxy());

   }

   public void addDatatype(String id, AttributeProxy proxy)
   {
      supportedDatatypes.put(id, proxy);
   }

   @Override
   public AttributeValue createValue(URI dataType, String value) throws UnknownIdentifierException, ParsingException
   {
      try
      {
         return getProxy(dataType.toString()).getInstance(value);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   @Override
   public AttributeValue createValue(Node root, String type) throws UnknownIdentifierException, ParsingException
   {
      try
      {
         return getProxy(type).getInstance(root);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   @Override
   public AttributeValue createValue(Node root, URI dataType) throws UnknownIdentifierException, ParsingException
   {
      return createValue(root, dataType.toString());
   }

   public static ExtendedAttributeFactory getFactory()
   {
      if (instance == null)
         instance = new ExtendedAttributeFactory();
      return instance;
   }

   private AttributeProxy getProxy(String type)
   {
      AttributeProxy proxy = (AttributeProxy) supportedDatatypes.get(type.toString());
      if (proxy == null)
         throw new RuntimeException("proxy null for " + type);
      return proxy;
   }
}
