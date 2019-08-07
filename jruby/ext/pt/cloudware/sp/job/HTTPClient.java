/*
 * coding: utf-8
 *
 * Copyright (c) 2019 Cloudware S.A. - All rights reserved.
 *
 * This file is part of sp-job
 */

package pt.cloudware.sp.job;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import java.io.StringWriter;
import java.io.PrintWriter;

import org.jruby.RubyHash;

public class HTTPClient
{

  private static boolean DEBUG = false;

  public static class Connection
  {

    public static class Timeouts {

      public final int connection;
      public final int request;

      public Timeouts (final int a_connection, final int a_request)
      {
        connection = a_connection;
        request    = a_request;
      }
  
    };

    public final Timeouts timeouts;

    public Connection (final Timeouts a_timeouts)
    {
        timeouts = a_timeouts;
    }

  };

  public static class Expect {

    public static class Content {

      public final String type;

      public Content (final String a_type)
      {
        type = a_type;
      }

    };

    public final int     code;
    public final Content content;
    
    public Expect (final int a_code, final Content a_content)
    {
        code    = a_code;
        content = a_content;
    }

  };

  public static class Response {

    public static class Content {

      public final String type;
      public final long   length;

      public Content (final String a_type, final long a_length)
      {
        type   = a_type;
        length = a_length;
      }

    };

    public final Integer code;
    public final String  body;
    public final Content content;

    public Response (final Integer a_code, final String a_body, final Content a_content)
    {
      code = a_code;
      body = a_body;
      content = a_content;
    }

  };

  public Response head (final String a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("HEAD", a_url, a_headers, /* a_body */ null, a_expect, a_connection);
  }

  public Response get (final String a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("GET", a_url, a_headers, /* a_body */ null, a_expect, a_connection);
  }

  public Response delete (final String a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("DELETE", a_url, a_headers, /* a_body */ null, a_expect, a_connection);
  }

  public Response post (final String a_url, final RubyHash a_headers, final String a_body,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("POST", a_url, a_headers, a_body, a_expect, a_connection);
  }

  public Response put (final String a_url, final RubyHash a_headers, final String a_body,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("PUT", a_url, a_headers, a_body, a_expect, a_connection);
  }

  public Response patch (final String a_url, final RubyHash a_headers, final String a_body,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("PATCH", a_url, a_headers, a_body, a_expect, a_connection);
  }

  private Response do_http (final String a_method, final String a_url, final RubyHash a_headers, final String a_body,
                                        final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    HttpURLConnection connection = null;
    Response          response   = null;
    Exception         exception  = null;

    if ( true == DEBUG ) {
      System.out.println("[JAVA][DEBUG] ~> " + a_method);
    }

    try {

      // ... open connection ...
      connection = (HttpURLConnection) new URL(a_url).openConnection();

      // ... set method and properties ...
      if ( true == a_method.equals("PATCH") ) {
        // ... HttpURLConnection does not support 'PATCH' method ...
        if ( true == DEBUG ) {
          System.out.println("[JAVA][DEBUG] - trying to set PATCH method ( brute-force )...");
        }
        // ... brute-force it ...
        try {
          final Object object;
          if ( connection instanceof sun.net.www.protocol.https.HttpsURLConnectionImpl ) {
              final java.lang.reflect.Field delegate = sun.net.www.protocol.https.HttpsURLConnectionImpl.class.getDeclaredField("delegate");
              delegate.setAccessible(true);
              object = delegate.get(connection);
          } else {
              object = connection;
          }
          final java.lang.reflect.Field field = HttpURLConnection.class.getDeclaredField("method");
          field.setAccessible(true);
          field.set(object, "PATCH");
        } catch (Exception ex) {
          // ... just for throwing expected 'not supported' exception ...
          connection.setRequestMethod(a_method);  
        }
      } else {
        connection.setRequestMethod(a_method);
      }

      // ... set headers ...
      connection.setRequestProperty("User-Agent", "SP-JOB/JAVA/HTTP-CLIENT");  
      for ( java.util.Iterator keySetIterator = a_headers.keySet().iterator(); keySetIterator.hasNext(); ) {
        final Object key   = keySetIterator.next();
        final Object value = a_headers.get(key);
        connection.setRequestProperty(String.valueOf(key), String.valueOf(value));
      }
  
      // ... if it's a POST, PUT or PATCH ...
      if ( true == a_method.equals("POST") || true == a_method.equals("PUT") || true == a_method.equals("PATCH") ) {        
        // ... we'll write data if we have a body set
        if ( null != a_body ) {
          connection.setDoOutput(true);
          new DataOutputStream(connection.getOutputStream()).write(a_body.getBytes(StandardCharsets.UTF_8));
        }
      }

      // ... read body ...
      BufferedReader in      = new BufferedReader(new InputStreamReader(connection.getInputStream()));
      StringBuilder  content = new StringBuilder();
      String line;
      while ( null != ( line = in.readLine() ) ) {
        content.append(line);
      }

      // ... set response ...
      response = new Response(connection.getResponseCode(), content.toString(), 
        new Response.Content(
          connection.getContentType(), connection.getContentLengthLong()
        )
      );
      
    } catch (Exception a_exception) {
      exception = a_exception;
    } finally {
      if ( true == DEBUG ) {
        System.out.println("[JAVA][DEBUG] - " + ( null != connection ? "closing connection" : "connection is not open"));
      }
      if ( null != connection ) {
        connection.disconnect();
      }
    }

    if ( null != exception ) {
      if ( true == DEBUG ) {
        System.out.println("[JAVA][DEBUG] <~ " + a_method + " => Exception: " + exception.getMessage()) ;
      }
      throw exception;
    }

    if ( true == DEBUG ) {
      System.out.println("[JAVA][DEBUG] <~ " + a_method);
    }

    return response;
  }

} // end of class 'HTTPClient'