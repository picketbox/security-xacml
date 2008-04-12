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
package org.jboss.security.xacml.factories;

import java.net.InetAddress;
import java.net.URI;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;

import org.jboss.security.xacml.core.model.context.AttributeType;
import org.jboss.security.xacml.core.model.context.AttributeValueType;
import org.jboss.security.xacml.interfaces.XMLSchemaConstants;
 

/**
 *  Construct Commonly Used Attributes in Request Subject/Resource/Action
 *  and Environment sections
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 20, 2007 
 *  @version $Revision$
 */
public class RequestAttributeFactory
{

   public static AttributeType createAnyURIAttributeType(String attrID, String issuer, URI value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, XMLSchemaConstants.DATATYPE_ANYURI);
   }

   public static AttributeType createBase64BinaryAttributeType(String attrID, String issuer, byte[] value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_BASE64BINARY);
   }

   public static AttributeType createBooleanAttributeType(String attrID, String issuer, boolean value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_BOOLEAN);
   }

   public static AttributeType createDateAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), XMLSchemaConstants.DATATYPE_DATE);
   }

   public static AttributeType createDateAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), XMLSchemaConstants.DATATYPE_DATE);
   }

   public static AttributeType createDateTimeAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), XMLSchemaConstants.DATATYPE_DATE_TIME);
   }

   public static AttributeType createDateTimeAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), XMLSchemaConstants.DATATYPE_DATE_TIME);
   }

   public static AttributeType createDNSNameAttributeType(String attrID, String issuer, String hostname)
   {
      return getBareAttributeType(attrID, issuer, hostname, XMLSchemaConstants.DATATYPE_DNSNAME);
   }

   public static AttributeType createDoubleAttributeType(String attrID, String issuer, double value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, XMLSchemaConstants.DATATYPE_DOUBLE);
   }

   public static AttributeType createEmailAttributeType(String attrID, String issuer, String value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_RFC822NAME);
   }

   public static AttributeType createHexBinaryAttributeType(String attrID, String issuer, byte[] value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_HEXBINARY);
   }

   public static AttributeType createIntegerAttributeType(String attrID, String issuer, int value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, XMLSchemaConstants.DATATYPE_INTEGER);
   }

   public static AttributeType createIPAddressAttributeType(String attrID, String issuer, InetAddress address)
   {
      return getBareAttributeType(attrID, issuer, address, XMLSchemaConstants.DATATYPE_IPADDRESS);
   }

   public static AttributeType createStringAttributeType(String attrID, String issuer, String value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_STRING);
   }

   public static AttributeType createTimeAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), XMLSchemaConstants.DATATYPE_TIME);
   }

   public static AttributeType createTimeAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), XMLSchemaConstants.DATATYPE_TIME);
   }

   public static AttributeType createX509NameAttributeType(String attrID, String issuer, X500Principal value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_X500NAME);
   }

   public static AttributeType createDayTimeDurationAttributeType(String attrID, String issuer, Duration value)
   {
      return getBareAttributeType(attrID, issuer, value.toString(), XMLSchemaConstants.DATATYPE_DAYTIMEDURATION);
   }

   public static AttributeType createYearMonthDurationAttributeType(String attrID, String issuer, Duration value)
   {
      return getBareAttributeType(attrID, issuer, value.toString(), XMLSchemaConstants.DATATYPE_YEARMONTHDURATION);
   }

   private static AttributeType getBareAttributeType(String attrID, String issuer, Object value, String dataType)
   {
      AttributeType attributeType = new AttributeType();
      attributeType.setAttributeId(attrID);
      attributeType.setDataType(dataType);
      if (issuer != null)
         attributeType.setIssuer(issuer);
      AttributeValueType avt = new AttributeValueType();
      avt.getContent().add(value);
      attributeType.getAttributeValue().add(avt);
      return attributeType;
   }

   private static String getXMLDate()
   {
      DatatypeFactory dtf;
      try
      {
         dtf = DatatypeFactory.newInstance();
      }
      catch (DatatypeConfigurationException e)
      {
         throw new RuntimeException(e);
      }
      XMLGregorianCalendar value = dtf.newXMLGregorianCalendar((GregorianCalendar) Calendar.getInstance());
      return value.toXMLFormat();
   }
}
