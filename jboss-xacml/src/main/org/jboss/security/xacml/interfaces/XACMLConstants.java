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

//$Id$

/**
 *  Constants
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public interface XACMLConstants
{
   String UNDERLYING_POLICY = "underlying_policy";
   String POLICY_FINDER = "policy_finder";
   String POLICY_FINDER_MODULE = "policy_finder_module";
   String REQUEST_CTX = "request_ctx";
   String RESPONSE_CTX = "response_ctx";
   
   String CONTEXT_SCHEMA = "urn:oasis:names:tc:xacml:2.0:context:schema:os";
   
   //Action Attribute IDs
   String ATTRIBUTEID_ACTION_ID = "urn:oasis:names:tc:xacml:1.0:action:action-id";
   String ATTRIBUTEID_IMPLIED_ACTION = "urn:oasis:names:tc:xacml:1.0:action:implied-action";
   String ATTRIBUTEID_ACTION_NAMESPACE = "urn:oasis:names:tc:xacml:1.0:action:action-namespace";
   
   //Environment Attribute IDs
   String ATTRIBUTEID_CURRENT_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
   String ATTRIBUTEID_CURRENT_DATE = "urn:oasis:names:tc:xacml:1.0:environment:current-date";
   String ATTRIBUTEID_CURRENT_DATE_TIME = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";
   
   //Resource Attribute IDs
   String ATTRIBUTEID_RESOURCE_ID = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
   String ATTRIBUTEID_TARGET_NAMESPACE = "urn:oasis:names:tc:xacml:2.0:resource:target-namespace";
   String ATTRIBUTEID_RESOURCE_LOCATION = "urn:oasis:names:tc:xacml:1.0:resource:resource-location";
   String ATTRIBUTEID_XPATH = "urn:oasis:names:tc:xacml:1.0:resource:xpath";
   String ATTRIBUTEID_SIMPLE_FILE_NAME = "urn:oasis:names:tc:xacml:1.0:resource:simple-file-name";
   
   //Subject Attribute IDs
   String ATTRIBUTEID_SUBJECT_ID = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
   String ATTRIBUTEID_ROLE = "urn:oasis:names:tc:xacml:2.0:subject:role";
   String ATTRIBUTEID_DNS_NAME = "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:dns-name";
   String ATTRIBUTEID_IP_ADDRESS = "urn:oasis:names:tc:xacml:1.0:subject:authn-locality:ip-address";
   String ATTRIBUTEID_AUTHENTICATION_METHOD = "urn:oasis:names:tc:xacml:1.0:subject:authentication-method";
   String ATTRIBUTEID_AUTHENTICATION_TIME = "urn:oasis:names:tc:xacml:1.0:subject:authentication-time";
   String ATTRIBUTEID_KEY_INFO = "urn:oasis:names:tc:xacml:1.0:subject:key-info";
   String ATTRIBUTEID_REQUEST_TIME = "urn:oasis:names:tc:xacml:1.0:subject:request-time";
   String ATTRIBUTEID_NAME_FORMAT = "urn:oasis:names:tc:xacml:1.0:subject:name-format";
   String ATTRIBUTEID_SESSION_START_TIME = "urn:oasis:names:tc:xacml:1.0:subject:session-start-time";
   String ATTRIBUTEID_SUBJECT_ID_QUALIFIER = "urn:oasis:names:tc:xacml:1.0:subject:subject-id-qualifier";
   String ATTRIBUTEID_ACCESS_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
   String ATTRIBUTEID_CODEBASE = "urn:oasis:names:tc:xacml:1.0:subject-category:codebase";
   String ATTRIBUTEID_INTERMEDIARY_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject";
   String ATTRIBUTEID_RECIPIENT_SUBJECT = "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";
   String ATTRIBUTEID_REQUESTING_MACHINE = "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine";
   
   //Begin Functions
   //Equal
   String FUNCTION_ANYURI_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:anyURI-equal";
   String FUNCTION_BASEBINARY_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-equal";
   String FUNCTION_BOOLEAN_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:boolean-equal";
   String FUNCTION_DATE_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:date-equal";
   String FUNCTION_DATETIME_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:dateTime-equal";
   String FUNCTION_DAYTIMEDURATION_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-equal";
   String FUNCTION_DOUBLE_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:double-equal";
   String FUNCTION_HEXBINARY_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-equal";
   String FUNCTION_INTEGER_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:integer-equal";
   String FUNCTION_RFC822NAME_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-equal";
   String FUNCTION_STRING_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-equal";
   String FUNCTION_TIME_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:time-equal";
   String FUNCTION_X500NAME_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:x500Name-equal";
   String FUNCTION_YEARMONTHDURATION_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-equal";
   
   //Abs
   String FUNCTION_DOUBLE_ABS = "urn:oasis:names:tc:xacml:1.0:function:double-abs";
   String FUNCTION_INTEGER_ABS = "urn:oasis:names:tc:xacml:1.0:function:integer-abs";
   
   //Add
   String FUNCTION_DOUBLE_ADD = "urn:oasis:names:tc:xacml:1.0:function:double-add";
   String FUNCTION_INTEGER_ADD = "urn:oasis:names:tc:xacml:1.0:function:integer-add";
   
   //Bag
   String FUNCTION_ANYURI_BAG = "urn:oasis:names:tc:xacml:1.0:function:anyURI-bag";
   String FUNCTION_ANYURI_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:anyURI-bag-size";
   String FUNCTION_ANYURI_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:anyURI-is-in";
   String FUNCTION_ANYURI_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:anyURI-one-and-only";
   String FUNCTION_BASE64BINARY_BAG = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-bag";
   String FUNCTION_BASE64BINARY_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-bag-size";
   String FUNCTION_BASE64BINARY_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-is-in";
   String FUNCTION_BASE64BINARY_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-one-and-only";
   String FUNCTION_BOOLEAN_BAG = "urn:oasis:names:tc:xacml:1.0:function:boolean-bag";
   String FUNCTION_BOOLEAN_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:boolean-bag-size";
   String FUNCTION_BOOLEAN_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:boolean-is-in";
   String FUNCTION_BOOLEAN_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:boolean-one-and-only";
   String FUNCTION_DATE_BAG = "urn:oasis:names:tc:xacml:1.0:function:date-bag";
   String FUNCTION_DATE_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:date-bag-size";
   String FUNCTION_DATE_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:date-is-in";
   String FUNCTION_DATE_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:date-one-and-only";
   String FUNCTION_DATETIME_BAG = "urn:oasis:names:tc:xacml:1.0:function:dateTime-bag";
   String FUNCTION_DATETIME_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:dateTime-bag-size";
   String FUNCTION_DATETIME_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:dateTime-is-in";
   String FUNCTION_DATETIME_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:dateTime-one-and-only";
   String FUNCTION_DAYTIMEDURATION_BAG = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-bag";
   String FUNCTION_DAYTIMEDURATION_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-bag-size";
   String FUNCTION_DAYTIMEDURATION_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-is-in";
   String FUNCTION_DAYTIMEDURATION_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-one-and-only";
   String FUNCTION_DOUBLE_BAG = "urn:oasis:names:tc:xacml:1.0:function:double-bag";
   String FUNCTION_DOUBLE_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:double-bag-size";
   String FUNCTION_DOUBLE_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:double-is-in";
   String FUNCTION_DOUBLE_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:double-one-and-only";
   String FUNCTION_HEXBINARY_BAG = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-bag";
   String FUNCTION_HEXBINARY_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-bag-size";
   String FUNCTION_HEXBINARY_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-is-in";
   String FUNCTION_HEXBINARY_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-one-and-only";
   String FUNCTION_INTEGER_BAG = "urn:oasis:names:tc:xacml:1.0:function:integer-bag";
   String FUNCTION_INTEGER_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:integer-bag-size";
   String FUNCTION_INTEGER_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:integer-is-in";
   String FUNCTION_INTEGER_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only";
   String FUNCTION_RFC822NAME_BAG = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-bag";
   String FUNCTION_RFC822NAME_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-bag-size";
   String FUNCTION_RFC822NAME_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-is-in";
   String FUNCTION_RFC822NAME_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-one-and-only";
   String FUNCTION_STRING_BAG = "urn:oasis:names:tc:xacml:1.0:function:string-bag";
   String FUNCTION_STRING_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:string-bag-size";
   String FUNCTION_STRING_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:string-is-in";
   String FUNCTION_STRING_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:string-one-and-only";
   String FUNCTION_TIME_BAG = "urn:oasis:names:tc:xacml:1.0:function:time-bag";
   String FUNCTION_TIME_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:time-bag-size";
   String FUNCTION_TIME_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:time-is-in";
   String FUNCTION_TIME_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:time-one-and-only";
   String FUNCTION_X500NAME_BAG = "urn:oasis:names:tc:xacml:1.0:function:x500Name-bag";
   String FUNCTION_X500NAME_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:x500Name-bag-size";
   String FUNCTION_X500NAME_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:x500Name-is-in";
   String FUNCTION_X500NAME_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:x500Name-one-and-only";
   String FUNCTION_YEARMONTHDURATION_BAG = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-bag";
   String FUNCTION_YEARMONTHDURATION_BAG_SIZE = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-bag-size";
   String FUNCTION_YEARMONTHDURATION_IS_IN = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-is-in";
   String FUNCTION_YEARMONTHDURATION_ONE_AND_ONLY = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-one-and-only";
   
   //Comparison
   String FUNCTION_DATE_GREATER_THAN = "urn:oasis:names:tc:xacml:1.0:function:date-greater-than";
   String FUNCTION_DATE_GREATER_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:date-greater-than-or-equal";
   String FUNCTION_DATE_LESS_THAN = "urn:oasis:names:tc:xacml:1.0:function:date-less-than";
   String FUNCTION_DATE_LESS_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:date-less-than-or-equal";
   String FUNCTION_DATETIME_GREATER_THAN = "urn:oasis:names:tc:xacml:1.0:function:dateTime-greater-than";
   String FUNCTION_DATETIME_GREATER_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:dateTime-greater-than-or-equal";
   String FUNCTION_DATETIME_LESS_THAN = "urn:oasis:names:tc:xacml:1.0:function:dateTime-less-than";
   String FUNCTION_DATETIME_LESS_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:dateTime-less-than-or-equal";
   String FUNCTION_DOUBLE_GREATER_THAN = "urn:oasis:names:tc:xacml:1.0:function:double-greater-than";
   String FUNCTION_DOUBLE_GREATER_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:double-greater-than-or-equal";
   String FUNCTION_DOUBLE_LESS_THAN = "urn:oasis:names:tc:xacml:1.0:function:double-less-than";
   String FUNCTION_DOUBLE_LESS_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:double-less-than-or-equal";
   String FUNCTION_INTEGER_GREATER_THAN = "urn:oasis:names:tc:xacml:1.0:function:integer-greater-than";
   String FUNCTION_INTEGER_GREATER_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:integer-greater-than-or-equal";
   String FUNCTION_INTEGER_LESS_THAN = "urn:oasis:names:tc:xacml:1.0:function:integer-less-than";
   String FUNCTION_INTEGER_LESS_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:integer-less-than-or-equal";
   String FUNCTION_STRING_GREATER_THAN = "urn:oasis:names:tc:xacml:1.0:function:string-greater-than";
   String FUNCTION_STRING_GREATER_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-greater-than-or-equal";
   String FUNCTION_STRING_LESS_THAN = "urn:oasis:names:tc:xacml:1.0:function:string-less-than";
   String FUNCTION_STRING_LESS_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:string-less-than-or-equal";
   String FUNCTION_TIME_IN_RANGE = "urn:oasis:names:tc:xacml:2.0:function:time-in-range";
   String FUNCTION_TIME_GREATER_THAN = "urn:oasis:names:tc:xacml:1.0:function:time-greater-than";
   String FUNCTION_TIME_GREATER_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:time-greater-than-or-equal";
   String FUNCTION_TIME_LESS_THAN = "urn:oasis:names:tc:xacml:1.0:function:time-less-than";
   String FUNCTION_TIME_LESS_THAN_OR_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:time-less-than-or-equal";
   
   //Date Math
   String FUNCTION_DATE_ADD_YEARMONTHDURATION = "urn:oasis:names:tc:xacml:1.0:function:date-add-yearMonthDuration";
   String FUNCTION_DATE_SUBTRACT_YEARMONTHDURATION = "urn:oasis:names:tc:xacml:1.0:function:date-subtract-yearMonthDuration";
   String FUNCTION_DATETIME_ADD_DAYTIMEDURATION = "urn:oasis:names:tc:xacml:1.0:function:dateTime-add-dayTimeDuration";
   String FUNCTION_DATETIME_SUBTRACT_DAYTIMEDURATION = "urn:oasis:names:tc:xacml:1.0:function:dateTime-subtract-dayTimeDuration";
   String FUNCTION_DATETIME_ADD_YEARMONTHDURATION = "urn:oasis:names:tc:xacml:1.0:function:dateTime-add-yearMonthDuration";
   String FUNCTION_DATETIME_SUBTRACT_YEARMONTHDURATION = "urn:oasis:names:tc:xacml:1.0:function:dateTime-subtract-yearMonthDuration";
   
   //Divide
   String FUNCTION_DOUBLE_DIVIDE = "urn:oasis:names:tc:xacml:1.0:function:double-divide";
   String FUNCTION_INTEGER_DIVIDE = "urn:oasis:names:tc:xacml:1.0:function:integer-divide";
   
   //Floor
   String FUNCTION_FLOOR = "urn:oasis:names:tc:xacml:1.0:function:floor";
   
   //High Order
   String FUNCTION_ALL_OF = "urn:oasis:names:tc:xacml:1.0:function:all-of";
   String FUNCTION_ALL_OF_ALL = "urn:oasis:names:tc:xacml:1.0:function:all-of-all";
   String FUNCTION_ALL_ANY = "urn:oasis:names:tc:xacml:1.0:function:all-any";
   String FUNCTION_ANY_OF = "urn:oasis:names:tc:xacml:1.0:function:any-of";
   String FUNCTION_ANY_OF_ALL = "urn:oasis:names:tc:xacml:1.0:function:any-of-all";
   String FUNCTION_ANY_OF_ANY = "urn:oasis:names:tc:xacml:1.0:function:any-of-any";
   
   //Logical
   String FUNCTION_AND = "urn:oasis:names:tc:xacml:1.0:function:and";
   String FUNCTION_OR = "urn:oasis:names:tc:xacml:1.0:function:or";
   String FUNCTION_NOT = "urn:oasis:names:tc:xacml:1.0:function:not";
   
   //Map
   String FUNCTION_MAP = "urn:oasis:names:tc:xacml:1.0:function:map";
   
   //Match
   String FUNCTION_REGEXP_URI_MATCH = "urn:oasis:names:tc:xacml:1.0:function:regexp-uri-match";
   String FUNCTION_REGEXP_DNSNAME_MATCH = "urn:oasis:names:tc:xacml:1.0:function:regexp-dnsName-match";
   String FUNCTION_REGEXP_IPADDRESS_MATCH = "urn:oasis:names:tc:xacml:1.0:function:regexp-ipAddress-match";
   String FUNCTION_RFC822NAME_MATCH = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-match";
   String FUNCTION_REGEXP_RFC822NAME_MATCH = "urn:oasis:names:tc:xacml:1.0:function:regexp-rfc822Name-match";
   String FUNCTION_REGEXP_STRING_MATCH = "urn:oasis:names:tc:xacml:1.0:function:regexp-string-match";
   String FUNCTION_X500NAME_MATCH = "urn:oasis:names:tc:xacml:1.0:function:x500Name-match";
   String FUNCTION_REGEXP_X500NAME_MATCH = "urn:oasis:names:tc:xacml:1.0:function:regexp-x500Name-match";
   
   //Mod
   String FUNCTION_INTEGER_MOD = "urn:oasis:names:tc:xacml:1.0:function:integer-mod";
   
   //Multiply
   String FUNCTION_DOUBLE_MULTIPLY = "urn:oasis:names:tc:xacml:1.0:function:double-multiply";
   String FUNCTION_INTEGER_MULTIPLY = "urn:oasis:names:tc:xacml:1.0:function:integer-multiply";
   
   //Nof
   String FUNCTION_N_OF = "urn:oasis:names:tc:xacml:1.0:function:n-of";
   
   //Numeric Convert
   String FUNCTION_DOUBLE_TO_INTEGER = "urn:oasis:names:tc:xacml:1.0:function:double-to-integer";
   String FUNCTION_INTEGER_TO_DOUBLE = "urn:oasis:names:tc:xacml:1.0:function:integer-to-double";
   
   //Round
   String FUNCTION_ROUND = "urn:oasis:names:tc:xacml:1.0:function:round";
   
   //Set
   String FUNCTION_ANYURI_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:anyURI-at-least-one-member-of";
   String FUNCTION_ANYURI_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:anyURI-intersection";
   String FUNCTION_ANYURI_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:anyURI-set-equals";
   String FUNCTION_ANYURI_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:anyURI-subset";
   String FUNCTION_ANYURI_UNION = "urn:oasis:names:tc:xacml:1.0:function:anyURI-union";
   String FUNCTION_BASE64BINARY_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-at-least-one-member-of";
   String FUNCTION_BASE64BINARY_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-intersection";
   String FUNCTION_BASE64BINARY_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-set-equals";
   String FUNCTION_BASE64BINARY_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-subset";
   String FUNCTION_BASE64BINARY_UNION = "urn:oasis:names:tc:xacml:1.0:function:base64Binary-union";
   String FUNCTION_BOOLEAN_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:boolean-at-least-one-member-of";
   String FUNCTION_BOOLEAN_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:boolean-intersection";
   String FUNCTION_BOOLEAN_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:boolean-set-equals";
   String FUNCTION_BOOLEAN_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:boolean-subset";
   String FUNCTION_BOOLEAN_UNION = "urn:oasis:names:tc:xacml:1.0:function:boolean-union";
   String FUNCTION_DATE_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:date-at-least-one-member-of";
   String FUNCTION_DATE_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:date-intersection";
   String FUNCTION_DATE_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:date-set-equals";
   String FUNCTION_DATE_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:date-subset";
   String FUNCTION_DATE_UNION = "urn:oasis:names:tc:xacml:1.0:function:date-union";
   String FUNCTION_DATETIME_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:dateTime-at-least-one-member-of";
   String FUNCTION_DATETIME_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:dateTime-intersection";
   String FUNCTION_DATETIME_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:dateTime-set-equals";
   String FUNCTION_DATETIME_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:dateTime-subset";
   String FUNCTION_DATETIME_UNION = "urn:oasis:names:tc:xacml:1.0:function:dateTime-union";
   String FUNCTION_DAYTIMEDURATION_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-at-least-one-member-of";
   String FUNCTION_DAYTIMEDURATION_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-intersection";
   String FUNCTION_DAYTIMEDURATION_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-set-equals";
   String FUNCTION_DAYTIMEDURATION_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-subset";
   String FUNCTION_DAYTIMEDURATION_UNION = "urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-union";
   String FUNCTION_DOUBLE_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:double-at-least-one-member-of";
   String FUNCTION_DOUBLE_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:double-intersection";
   String FUNCTION_DOUBLE_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:double-set-equals";
   String FUNCTION_DOUBLE_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:double-subset";
   String FUNCTION_DOUBLE_UNION = "urn:oasis:names:tc:xacml:1.0:function:double-union";
   String FUNCTION_HEXBINARY_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-at-least-one-member-of";
   String FUNCTION_HEXBINARY_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-intersection";
   String FUNCTION_HEXBINARY_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-set-equals";
   String FUNCTION_HEXBINARY_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-subset";
   String FUNCTION_HEXBINARY_UNION = "urn:oasis:names:tc:xacml:1.0:function:hexBinary-union";
   String FUNCTION_INTEGER_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:integer-at-least-one-member-of";
   String FUNCTION_INTEGER_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:integer-intersection";
   String FUNCTION_INTEGER_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:integer-set-equals";
   String FUNCTION_INTEGER_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:integer-subset";
   String FUNCTION_INTEGER_UNION = "urn:oasis:names:tc:xacml:1.0:function:integer-union";
   String FUNCTION_RFC822NAME_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-at-least-one-member-of";
   String FUNCTION_RFC822NAME_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-intersection";
   String FUNCTION_RFC822NAME_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-set-equals";
   String FUNCTION_RFC822NAME_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-subset";
   String FUNCTION_RFC822NAME_UNION = "urn:oasis:names:tc:xacml:1.0:function:rfc822Name-union";
   String FUNCTION_STRING_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of";
   String FUNCTION_STRING_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:string-intersection";
   String FUNCTION_STRING_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:string-set-equals";
   String FUNCTION_STRING_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:string-subset";
   String FUNCTION_STRING_UNION = "urn:oasis:names:tc:xacml:1.0:function:string-union";
   String FUNCTION_TIME_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:time-at-least-one-member-of";
   String FUNCTION_TIME_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:time-intersection";
   String FUNCTION_TIME_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:time-set-equals";
   String FUNCTION_TIME_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:time-subset";
   String FUNCTION_TIME_UNION = "urn:oasis:names:tc:xacml:1.0:function:time-union";
   String FUNCTION_X500NAME_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:x500Name-at-least-one-member-of";
   String FUNCTION_X500NAME_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:x500Name-intersection";
   String FUNCTION_X500NAME_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:x500Name-set-equals";
   String FUNCTION_X500NAME_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:x500Name-subset";
   String FUNCTION_X500NAME_UNION = "urn:oasis:names:tc:xacml:1.0:function:x500Name-union";
   String FUNCTION_YEARMONTHDURATION_AT_LEAST_ONE_MEMBER_OF = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-at-least-one-member-of";
   String FUNCTION_YEARMONTHDURATION_INTERSECTION = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-intersection";
   String FUNCTION_YEARMONTHDURATION_SET_EQUALS = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-set-equals";
   String FUNCTION_YEARMONTHDURATION_SUBSET = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-subset";
   String FUNCTION_YEARMONTHDURATION_UNION = "urn:oasis:names:tc:xacml:1.0:function:yearMonthDuration-union";
   
   //String Concatenate
   String FUNCTION_STRING_CONCATENATE = "urn:oasis:names:tc:xacml:2.0:function:string-concatenate";
   String FUNCTION_URL_STRING_CONCATENATE = "urn:oasis:names:tc:xacml:2.0:function:url-string-concatenate";
   
   //String Normalize
   String FUNCTION_STRING_NORMALIZE_SPACE = "urn:oasis:names:tc:xacml:1.0:function:string-normalize-space";
   String FUNCTION_STRING_NORMALIZE_TO_LOWER_CASE = "urn:oasis:names:tc:xacml:1.0:function:string-normalize-to-lower-case";
   
   //Subtract
   String FUNCTION_DOUBLE_SUBTRACT = "urn:oasis:names:tc:xacml:1.0:function:double-subtract";
   String FUNCTION_INTEGER_SUBTRACT = "urn:oasis:names:tc:xacml:1.0:function:integer-subtract";
   
   //XPath
   String FUNCTION_XPATH_NODE_COUNT = "urn:oasis:names:tc:xacml:1.0:function:xpath-node-count";
   String FUNCTION_XPATH_NODE_EQUAL = "urn:oasis:names:tc:xacml:1.0:function:xpath-node-equal";
   String FUNCTION_XPATH_NODE_MATCH = "urn:oasis:names:tc:xacml:1.0:function:xpath-node-match";
   //End Functions
   
   //Rule Combining Algorithms
   String RULE_COMBINING_FIRST_APPLICABLE = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable";
   String RULE_COMBINING_DENY_OVERRIDES = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides";
   String RULE_COMBINING_ORDERED_DENY_OVERRIDES = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:ordered-deny-overrides";
   String RULE_COMBINING_PERMIT_OVERRIDES = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides";
   String RULE_COMBINING_ORDERED_PERMIT_OVERRIDES = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:ordered-permit-overrides";
   
   /**
    * The decision to permit the request
    */
   public static final int DECISION_PERMIT = 0;

   /**
    * The decision to deny the request
    */
   public static final int DECISION_DENY = 1;

   /**
    * The decision that a decision about the request cannot be made
    */
   public static final int DECISION_INDETERMINATE = 2;

   /**
    * The decision that nothing applied to us
    */
   public static final int DECISION_NOT_APPLICABLE = 3;
}
