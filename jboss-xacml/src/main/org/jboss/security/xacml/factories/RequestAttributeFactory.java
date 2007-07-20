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

import org.jboss.security.xacml.core.model.context.AttributeType;
import org.jboss.security.xacml.core.model.context.AttributeValueType;

//$Id$

/**
 *  Construct Commonly Used Attributes in Request Subject/Resource/Action
 *  and Environment sections
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 20, 2007 
 *  @version $Revision$
 */
public class RequestAttributeFactory
{
   
   public static AttributeType createIntegerAttributeType(String attrID, String issuer, int value)
   {
      AttributeType attributeType = new AttributeType();
      attributeType.setAttributeId(attrID);
      attributeType.setDataType("http://www.w3.org/2001/XMLSchema#integer"); 
      if(issuer != null)
         attributeType.setIssuer(issuer);
      AttributeValueType avt = new AttributeValueType();
      avt.getContent().add("" + value);
      attributeType.getAttributeValue().add(avt);
      return attributeType;
   }
   
   public static AttributeType createStringAttributeType(String attrID, String issuer, String value)
   {
      AttributeType attributeType = new AttributeType();
      attributeType.setAttributeId(attrID);
      attributeType.setDataType("http://www.w3.org/2001/XMLSchema#string");  
      if(issuer != null)
         attributeType.setIssuer(issuer);
      AttributeValueType avt = new AttributeValueType();
      avt.getContent().add(value);
      attributeType.getAttributeValue().add(avt);
      return attributeType;
   }

}
