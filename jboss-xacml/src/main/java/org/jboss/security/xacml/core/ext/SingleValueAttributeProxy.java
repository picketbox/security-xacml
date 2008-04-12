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
import java.net.URISyntaxException;

import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.SunxacmlUtil;
import org.jboss.security.xacml.sunxacml.UnknownIdentifierException;
import org.jboss.security.xacml.sunxacml.attr.AttributeFactory;
import org.jboss.security.xacml.sunxacml.attr.AttributeProxy;
import org.jboss.security.xacml.sunxacml.attr.AttributeValue;
import org.jboss.security.xacml.sunxacml.attr.StringAttribute;
import org.w3c.dom.Node;

/**
 *  Represents a single value attribute proxy
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 28, 2008 
 *  @version $Revision$
 */
public class SingleValueAttributeProxy implements AttributeProxy
{
   private URI type;

   public SingleValueAttributeProxy(String type)
   {
      try
      {
         this.type = new URI(type);
      }
      catch (URISyntaxException e)
      {
         throw new RuntimeException(e);
      }
   }

   public SingleValueAttributeProxy(URI type)
   {
      this.type = type;
   }

   public AttributeValue getInstance(Node root) throws Exception
   {
      // now we get the attribute value
      if (SunxacmlUtil.getNodeName(root).equals("AttributeValue"))
      {
         // now get the value
         try
         {
            Node child = root.getFirstChild();
            if (child == null)
               return new StringAttribute("");
            //get the type of the node
            short nodetype = child.getNodeType();

            // now see if we have (effectively) a simple string value
            if ((nodetype == Node.TEXT_NODE) || (nodetype == Node.CDATA_SECTION_NODE)
                  || (nodetype == Node.COMMENT_NODE))
            {
               return new StringAttribute(child.getNodeValue());
            }

            return AttributeFactory.getInstance().createValue(child, type);
         }
         catch (UnknownIdentifierException uie)
         {
            throw new ParsingException("Unknown AttributeId", uie);
         }
      }
      return null;
   }

   public AttributeValue getInstance(String value) throws Exception
   {
      return new SingleValueAttribute(type, value);
   } 
}
