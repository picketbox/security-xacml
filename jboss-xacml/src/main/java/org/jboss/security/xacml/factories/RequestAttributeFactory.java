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
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

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
   /**
    * Create an attribute that is of URI type
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createAnyURIAttributeType(String attrID, String issuer, URI value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, XMLSchemaConstants.DATATYPE_ANYURI);
   }

   /**
    * Create Base64 attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createBase64BinaryAttributeType(String attrID, String issuer, byte[] value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_BASE64BINARY);
   }

   /**
    * Create Boolean attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createBooleanAttributeType(String attrID, String issuer, boolean value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_BOOLEAN);
   }

   /**
    * Create Date attribute
    * @param attrID
    * @param issuer
    * @return
    */
   public static AttributeType createDateAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), XMLSchemaConstants.DATATYPE_DATE);
   }

   /**
    * Create Date attribute with the passed {@link XMLGregorianCalendar}
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createDateAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), XMLSchemaConstants.DATATYPE_DATE);
   }

   /**
    * Create Date Time Attribute
    * @param attrID
    * @param issuer
    * @return
    */
   public static AttributeType createDateTimeAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), XMLSchemaConstants.DATATYPE_DATE_TIME);
   }
   /**
    * Create Date Time attribute with the passed {@link XMLGregorianCalendar}
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createDateTimeAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), XMLSchemaConstants.DATATYPE_DATE_TIME);
   }

   /**
    * Create DNS Name Attribute
    * @param attrID
    * @param issuer
    * @param hostname
    * @return
    */
   public static AttributeType createDNSNameAttributeType(String attrID, String issuer, String hostname)
   {
      return getBareAttributeType(attrID, issuer, hostname, XMLSchemaConstants.DATATYPE_DNSNAME);
   }

   /**
    * Create Double Attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createDoubleAttributeType(String attrID, String issuer, double value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, XMLSchemaConstants.DATATYPE_DOUBLE);
   }

   /**
    * Create Email Attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createEmailAttributeType(String attrID, String issuer, String value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_RFC822NAME);
   }

   /**
    * Create Hex Binary attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createHexBinaryAttributeType(String attrID, String issuer, byte[] value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_HEXBINARY);
   }

   /**
    * Create Integer Attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createIntegerAttributeType(String attrID, String issuer, int value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, XMLSchemaConstants.DATATYPE_INTEGER);
   }

   /**
    * Create IP Address attribute
    * @param attrID
    * @param issuer
    * @param address
    * @return
    */
   public static AttributeType createIPAddressAttributeType(String attrID, String issuer, InetAddress address)
   {
      return getBareAttributeType(attrID, issuer, address, XMLSchemaConstants.DATATYPE_IPADDRESS);
   }

   /**
    * Create String attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createStringAttributeType(String attrID, String issuer, String value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_STRING);
   }

   /**
    * Create Time attribute
    * @param attrID
    * @param issuer
    * @return
    */
   public static AttributeType createTimeAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), XMLSchemaConstants.DATATYPE_TIME);
   }

   /**
    * Create Time Attribute with the passed {@link XMLGregorianCalendar}
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createTimeAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), XMLSchemaConstants.DATATYPE_TIME);
   }

   /**
    * Create X509 attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createX509NameAttributeType(String attrID, String issuer, X500Principal value)
   {
      return getBareAttributeType(attrID, issuer, value, XMLSchemaConstants.DATATYPE_X500NAME);
   }

   /**
    * Create DayTimeDuration attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createDayTimeDurationAttributeType(String attrID, String issuer, Duration value)
   {
      return getBareAttributeType(attrID, issuer, value.toString(), XMLSchemaConstants.DATATYPE_DAYTIMEDURATION);
   }

   /**
    * Create year month duration attribute
    * @param attrID
    * @param issuer
    * @param value
    * @return
    */
   public static AttributeType createYearMonthDurationAttributeType(String attrID, String issuer, Duration value)
   {
      return getBareAttributeType(attrID, issuer, value.toString(), XMLSchemaConstants.DATATYPE_YEARMONTHDURATION);
   }
   
   /**
    * Create multi valued attribute
    * @param attrID
    * @param issuer
    * @param dataType
    * @param values
    * @return
    */
   public static AttributeType createMultiValuedAttributeType(String attrID, String issuer, String dataType, String[] values)
   {
      AttributeType attributeType = new AttributeType();
      attributeType.setAttributeId(attrID);
      attributeType.setDataType(dataType);
      if (issuer != null)
         attributeType.setIssuer(issuer);
      
      List<String> valueList = Arrays.asList(values);
      
      AttributeValueType avt = new AttributeValueType();
      avt.getContent().addAll(valueList);
      attributeType.getAttributeValue().add(avt);
      return attributeType; 
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