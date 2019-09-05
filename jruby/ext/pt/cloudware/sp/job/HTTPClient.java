/*
 * coding: utf-8
 *
 * Copyright (c) 2019 Cloudware S.A. - All rights reserved.
 *
 * This file is part of sp-job
 */

package pt.cloudware.sp.job;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.StringWriter;
import java.io.PrintWriter;

import java.io.FileNotFoundException;

import org.jruby.RubyHash;

import java.util.List;
import java.util.Map;

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

      public Content (final String type, final long length)
      {
        this.type   = type;
        this.length = length;
      }

    };

    public final Integer code;
    public final String  body;
    public final Content content;

    public Response (final Integer code, final String body, final Content content)
    {
      this.code = code;
      this.body = body;
      this.content = content;
    }

  };

  public Response head (final String a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("HEAD", a_url, a_headers, /* a_body */ (String)null, a_expect, a_connection);
  }

  public Response get (final String a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("GET", a_url, a_headers, /* a_body */ (String)null, a_expect, a_connection);
  }

  public Response delete (final String a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("DELETE", a_url, a_headers, /* a_body */ (String)null, a_expect, a_connection);
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
 
  /*         */
  /* --- --- */
  /*/        */

  public Response get_to_file (final String a_url, final RubyHash a_headers, final String a_to,
                               final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception, URISyntaxException
  {
    return do_http("GET", a_url, a_headers, /* a_from */ (URI)null, new URI(a_to), a_expect, a_connection);
  }

  public Response post_to_file (final String a_url, final RubyHash a_headers, final String a_body, final String a_to,
                                final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception, URISyntaxException
  {
    return _do_http("POST", a_url, a_headers, /* a_stream */ new InputStream(a_body), new OutputStream(new URI("file://" + a_to)), a_expect, a_connection);
  }


  /*         */
  /* --- --- */
  /*/        */

  /*
   * Perform an HTTP POST request to send a local file ( a_from ) to an url ( a_to ). 
   */
  public Response post_file (final String a_from, final String a_to, final RubyHash a_headers,
                             final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("POST", /* a_url */ a_to, a_headers, new URI(a_from), a_expect, a_connection);
  }

  /*
   * Perform an HTTP PUT request to send a local file ( a_from ) to an url ( a_to ). 
   */
  public Response put_file (final String a_from, final String a_to, final RubyHash a_headers,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("PUT", /* a_url */ a_to, a_headers, new URI(a_from), a_expect, a_connection);
  }

  /*
   * Perform an HTTP PATCH request to send a local file ( a_from ) to an url ( a_to ). 
   */
  public Response patch_file (final String a_from, final String a_to, final RubyHash a_headers,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http("PATCH", /* a_url */ a_to, a_headers, new URI(a_from), a_expect, a_connection);
  }

  /*         */
  /* --- --- */
  /*/        */

  private Response do_http (final String a_method, final String a_url, final RubyHash a_headers, final String a_body,
                            final Expect a_expect, final Connection a_connection)
    throws MalformedURLException, ProtocolException, IOException, Exception
    {
      return _do_http(a_method, a_url, a_headers, /* a_stream */ new InputStream(a_body), new OutputStream(), a_expect, a_connection);
  }

  private Response do_http (final String a_method, final String a_url, final RubyHash a_headers, final URI a_from,
                            final Expect a_expect, final Connection a_connection)
    throws MalformedURLException, ProtocolException, IOException, Exception
    {
      return _do_http(a_method, a_url, a_headers, /* a_stream */ new InputStream(new URI("file://" + a_from.getPath())), new OutputStream(), a_expect, a_connection);
  }
  

  private Response do_http (final String a_method, final String a_url, final RubyHash a_headers, final URI a_from, final URI a_to,
                            final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    if ( null != a_from ) {
      return _do_http(a_method, a_url, a_headers, /* a_stream */ new InputStream(new URI("file://" + a_from.getPath())), new OutputStream(new URI("file://" + a_to.getPath())), a_expect, a_connection);
    } else {
      return _do_http(a_method, a_url, a_headers, /* a_stream */ (InputStream)null, new OutputStream(new URI("file://" + a_to.getPath())), a_expect, a_connection);
    }
  }

  /*         */
  /* --- --- */
  /*         */ 

  private static class Stream 
  {

    protected String data = null;
    protected URI    uri  = null;

    public Stream(final String data)
    {
      this.data = data;
      this.uri  = null;
    }

    public Stream(final URI uri)
    {
      this.data = null;
      this.uri  = uri;
    }

    public final URI uri ()
    {
      return this.uri;
    }

  }

  private static class InputStream extends Stream
  {


    public InputStream(final String data)
    {
      super(data);
    }

    public InputStream(final URI uri)
    {
      super(uri);
    }

    public void write (HttpURLConnection a_connection)
      throws MalformedURLException, ProtocolException, IOException, Exception, FileNotFoundException
    {
      if ( null != data ) {
        new DataOutputStream(a_connection.getOutputStream()).write(data.getBytes(StandardCharsets.UTF_8));
      } else if ( null != uri ) {

        final BufferedOutputStream output = new BufferedOutputStream(a_connection.getOutputStream());
        final BufferedInputStream  input  = new BufferedInputStream(new FileInputStream(uri.getPath()));

        byte[] buff = new byte[1024*1024];
        int len;
        while ( ( len = input.read(buff)) > 0 ) {
          output.write(buff, 0, len);
        }
        input.close();
        output.flush();
			  output.close();
      }
    }

    public long length () 
      throws IOException, Exception
    {
      if ( null != data ) {
        return (long)data.length();
      } else if ( null != uri ) {
        final File file = new File(uri);
        if ( false == file.exists() ) {
          throw new FileNotFoundException();
        }
        return file.length();
      }
      return 0;
    }
    
  };

  /*         */
  /* --- --- */
  /*/        */
  private static class OutputStream  extends Stream
  {

    private FileOutputStream stream = null;

    public OutputStream()
    {
      super(new String());
      this.stream = null;
    }

    public OutputStream(final URI uri) 
      throws FileNotFoundException
    {
      super(uri);
      this.stream = new FileOutputStream(uri.getPath());
    }

    public void write (final byte[] bytes, final int length, final String contentType)
    throws Exception
    {
      if ( null != stream ) {
        this.stream.write(bytes, 0, length);
      } else {
        if ( true == contentType.startsWith("application/json") || true == contentType.startsWith("application/vnd.api+json") ) {
          this.data += new String(bytes, /* offset */ 0, /* length */ length, /* charset */ StandardCharsets.UTF_8);
        } else {
          this.data += new String(bytes, /* offset */ 0, /* length */ length, /* charset */ StandardCharsets.ISO_8859_1);
        }
      }
    }

    public final String content ()
    {
      if ( null != uri ) {
        return uri.getPath();
      }
      return data;
    }

  };

  /*         */
  /* --- --- */
  /*/        */
  private Response _do_http (final String a_method, final String a_url, final RubyHash a_headers, final InputStream a_input_stream, final OutputStream a_output_stream,
                            final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    HttpURLConnection connection = null;
    Response          response   = null;
    Exception         exception  = null;
    String            responseBody = null;

    if ( true == DEBUG ) {
      System.out.println("[JAVA][DEBUG] ~> METHOD  - " + a_method);
      System.out.println("[JAVA][DEBUG] ~> URL     - " + a_url);
      if ( true == a_method.equals("POST") || true == a_method.equals("PUT") || true == a_method.equals("PATCH") ) {
        if ( null != a_input_stream.uri() ) {
          System.out.println("[JAVA][DEBUG] - TX BODY - IS A FILE @ " + a_input_stream.uri().getPath());
        } else {
          System.out.println("[JAVA][DEBUG] - TX BODY - IS A STRING");
        }
      }
      if ( null != a_output_stream.uri() ) {
        System.out.println("[JAVA][DEBUG] - RX BODY - IS A FILE @ " + a_output_stream.uri().getPath());
      } else {
        System.out.println("[JAVA][DEBUG] - RX BODY - IS A STRING");
      }
    }

    try {

      // ... open connection ...
      connection = (HttpURLConnection) new URL(a_url).openConnection();

      // ... set method and properties ...
      if ( true == a_method.equals("PATCH") ) {
        // ... HttpURLConnection does not support 'PATCH' method ...
        if ( true == DEBUG ) {
          System.out.println("[JAVA][DEBUG] - HACK    - trying to set PATCH method ( brute-force )...");
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
          // ... expected 'not supported' exception ...
          // ... this set must be called here ! - do not move it !
          connection.setRequestMethod(a_method);
        }
      } else {
        // ... this set must be called here ! - do not move it !
        connection.setRequestMethod(a_method);
      }

      // ... set headers ...
      connection.setRequestProperty("User-Agent", "SP-JOB/JAVA/HTTP-CLIENT");

      if ( null != a_headers ) {
        for ( java.util.Iterator keySetIterator = a_headers.keySet().iterator(); keySetIterator.hasNext(); ) {
          final Object key   = keySetIterator.next();
          final Object value = a_headers.get(key);
          connection.setRequestProperty(String.valueOf(key), String.valueOf(value));
          if ( true == DEBUG ) {
            System.out.println("[JAVA][DEBUG] - HEADER  - " + String.valueOf(key) + ": " + String.valueOf(value));
          }
        }
      }

      // ... if it's a POST, PUT or PATCH ...
      if ( true == a_method.equals("POST") || true == a_method.equals("PUT") || true == a_method.equals("PATCH") ) {

        final long content_length = a_input_stream.length();
        if ( true == DEBUG ) {
          System.out.println("[JAVA][DEBUG] - TX      - Content-Length: " + content_length);
        }

        // ... we'll write data if we have a data to send ...
        if ( content_length > 0 ) {
          // ... fix 'Content-Length' header ...
          connection.setFixedLengthStreamingMode(content_length);        
          // ... signal we want to write ...
          connection.setDoOutput(true);
          if ( true == DEBUG ) {
            System.out.println("[JAVA][DEBUG] - TX      - Writing data...");
          }
            // ... write data ...
          a_input_stream.write(connection);
        }

      }

      //
      // ... RESPONSE ...
      //
      final int    responseCode        = connection.getResponseCode();
      final String responseContentType = connection.getContentType();

      if ( true == DEBUG ) {
        System.out.println("[JAVA][DEBUG] - RX      - Status Code   : " + responseCode);
        System.out.println("[JAVA][DEBUG] - RX      - Content-Type  : " + responseContentType );
        System.out.println("[JAVA][DEBUG] - RX      - Content-Length: " + connection.getContentLengthLong());
      }

      // ... set response ...
      if ( 204 == responseCode ) {
        // ... no body ...
        response = new Response(connection.getResponseCode(), responseBody, /* content */ null);
      } else {
        // ... read body ...
        byte[] chunk = new byte[2048];
        final DataInputStream responseStream;
        if ( responseCode >= 400 && responseCode <= 499 ) {
          responseStream = new DataInputStream((java.io.FilterInputStream)connection.getErrorStream());
        } else {
          responseStream = new DataInputStream((java.io.FilterInputStream)connection.getContent());
        }
        int length = 0;
        while ( -1 != ( length = responseStream.read(chunk, 0, chunk.length) ) ) {
          a_output_stream.write(chunk, length, responseContentType);
        } 
        responseBody = a_output_stream.content();
        // if ( true == DEBUG ) {
        //   System.out.println("[JAVA][DEBUG] - RX      - " + responseBody);
        // }
        response = new Response(connection.getResponseCode(), responseBody,
          new Response.Content(
            connection.getContentType(), connection.getContentLengthLong()
          )
        );
      }
    } catch (Exception a_exception) {
      exception = a_exception;
    } finally {
      if ( true == DEBUG ) {
        System.out.println("[JAVA][DEBUG] -         - C" + ( null != connection ? "losing connection" : "onnection is not open"));
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
