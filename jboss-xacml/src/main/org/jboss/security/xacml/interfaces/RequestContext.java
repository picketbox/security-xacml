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
package org.jboss.security.xacml.interfaces;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jboss.security.xacml.core.model.context.RequestType;

//$Id$

/**
 *  Represents a Request
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public interface RequestContext extends ContextMapOp
{ 
   /**
    * Place the Request instance on the context
    * @param requestType An instance of RequestType 
    * @throws IOException
    */
   void setRequest(RequestType requestType) throws IOException;
   
   /**
    * Read the Request from a stream
    * @param is InputStream for the request 
    * @throws IOException
    */
   void readRequest(InputStream is) throws IOException;
   
   /**
    * Marshall the request context onto an Output Stream
    * @param os OutputStream (System.out, ByteArrayOutputStream etc)
    * @throws IOException
    */
   void marshall(OutputStream os) throws IOException;
} 