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
package org.jboss.test.security.xacml.ldap;

import java.io.File;
import java.net.URL;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import org.opends.server.tools.LDAPCompare;
import org.opends.server.tools.LDAPDelete;
import org.opends.server.tools.LDAPModify;
import org.opends.server.tools.LDAPSearch;

/**
 *  Utility class that deals with the integrated ldap (OpenDS)
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @version $Revision$
 *  @since  Sep 15, 2006
 */
public class OpenDSUtil
{
   private static final Logger log = Logger.getLogger(OpenDSUtil.class.getName());

   public OpenDSUtil()
   {
   }

   /**
    * Add a LDIF file into the Directory Server
    * @param serverHost Server Host (Use getServerHost() of JBossTestxxx)
    * @param port Port for the DS
    * @param admin admin dn ("cn=Directory Manager")
    * @param adminpwd (password)
    * @param ldifURL (use getDeployURL of JBossTestxxx)
    * @return whether the add was success
    */
   public boolean addLDIF(String serverHost, String port, String admin, String adminpwd, URL ldifURL)
   {
      File ldifFile = new File(ldifURL.getPath());
      if (!ldifFile.exists())
         throw new IllegalArgumentException("LDIF file:" + ldifURL + " does not exist");
      String[] cmd = new String[]
      {"-h", serverHost, "-p", port, "-D", admin, "-w", adminpwd, "-a", "-f", ldifFile.getPath()};
      log.fine("addLDIF:" + print(cmd));
      return LDAPModify.mainModify(cmd, false, System.out, System.err) == 0;
   }

   /**
    * Delete a DN in the Directory Server
   * @param serverHost Server Host (Use getServerHost() of JBossTestxxx)
    * @param port Port for the DS
    * @param admin admin dn ("cn=Directory Manager")
    * @param adminpwd (password)
    * @param dnToDelete DN to delete (Eg: dc=jboss,dc=org)
    * @param recursive should children also go?
    * @return whether the delete op was success
    */
   public boolean deleteDN(String serverHost, String port, String admin, String adminpwd, String dnToDelete,
         boolean recursive)
   {
      System.out.println("Start delete DN");
      String rec = recursive ? "-x" : " ";

      String[] cmd = new String[]
      {"-h", serverHost, "-p", port, "-D", admin, "-w", adminpwd, "-V", "3", rec, "--noPropertiesFile", dnToDelete};
      log.fine("deleteDN:" + print(cmd));
      boolean result = LDAPDelete.mainDelete(cmd, false, System.out, System.err) == 0;
      System.out.println("END delete DN");
      return result;
   }

   /**
    * Recursively delete a DN
    * @param serverHost
    * @param port
    * @param admin
    * @param adminpwd
    * @param dnToDelete
    * @return
    */
   public boolean deleteDNRecursively(String serverHost, String port, String admin, String adminpwd, String dnToDelete)
   {
      String[] args =
      {"-h", serverHost, "-p", port, "-V", "3", "-D", admin, "-w", adminpwd, "-x", "--noPropertiesFile", dnToDelete};

      boolean result = LDAPDelete.mainDelete(args, false, System.out, System.err) == 0;
      return result;
   }

   /**
    * Check whether a DN exists. Typically before you do a ldap delete
    * @param serverHost
    * @param port
    * @param dn
    * @return whether the DN exists?
    */
   public boolean existsDN(String serverHost, String port, String dn)
   {
      System.out.println("Start Search");
      String[] cmd = new String[]
      {"-h", serverHost, "-p", port, "-b", dn, "-s", "sub", "objectclass=*"};
      log.fine("existsDN:" + print(cmd));
      boolean result = LDAPSearch.mainSearch(cmd) == 0;
      System.out.println("End Search");
      return result;
   }

   /**
    * Issue a ldapCompare in the standard ldapCompare cmd line syntax
    * (Eg: "-h localhost -p 1389 -D "cn=..." -w password -a -f ldif.txt)
    * @param cmdline
    * @return whether ldapCompare was success
    */
   public boolean ldapCompare(String cmdline)
   {
      String[] strArr = getStringArr(cmdline);
      log.fine("ldapCompare:" + print(strArr));
      return LDAPCompare.mainCompare(strArr) == 0;
   }

   /**
    * Issue a ldapdelete in the standard ldapdelete cmd line syntax
    * (Eg: "-h localhost -p 1389 -D "cn=..." -w password -a -f ldif.txt)
    * @param cmdline
    * @return whether ldapmodify was success
    */
   public boolean ldapDelete(String cmdline)
   {
      String[] strArr = getStringArr(cmdline);
      log.fine("ldapDelete:" + print(strArr));
      return LDAPDelete.mainDelete(strArr) == 0;
   }

   /**
    * Issue a ldapmodify in the standard ldapmodify cmd line syntax
    * (Eg: "-h localhost -p 1389 -D "cn=..." -w password -a -f ldif.txt)
    * @param cmdline
    * @return whether ldapmodify was success
    */
   public boolean ldapModify(String cmdline)
   {
      String[] strArr = getStringArr(cmdline);
      log.fine("ldapModify:" + print(strArr));
      return LDAPModify.mainModify(strArr) == 0;
   }

   //***************************************************************
   //   PRIVATE METHODS
   //***************************************************************
   private String[] getStringArr(String str)
   {
      StringTokenizer st = new StringTokenizer(str);
      int num = st.countTokens();
      String[] strarr = new String[num];
      int i = 0;
      while (st.hasMoreTokens())
      {
         strarr[i++] = st.nextToken();
      }
      return strarr;
   }

   private String print(String[] arr)
   {
      StringBuilder sb = new StringBuilder();
      int len = arr != null ? arr.length : 0;
      for (int i = 0; i < len; i++)
         sb.append(arr[i]).append(" ");
      return sb.toString();
   }
}
