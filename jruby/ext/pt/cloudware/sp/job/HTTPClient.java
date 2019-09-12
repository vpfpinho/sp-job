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
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.Ruby;
import org.jruby.javasupport.JavaEmbedUtils;

import java.util.List;
import java.util.Map;

import org.jcodings.Encoding;

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

      public final RubyString type;

      public Content (final RubyString a_type)
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

      public final RubyString type;
      public final long   length;

      public Content (final RubyString type, final long length)
      {
        this.type   = type;
        this.length = length;
      }

    };

    public final Integer    code;
    public final RubyString body;
    public final Content    content;

    public Response (final Integer code, final RubyString body, final Content content)
    {
      this.code = code;
      this.body = body;
      this.content = content;
    }

  };

  private static class JRubyHelper {

    public static RubyString toRubyString (final Ruby runtime, final String value)
    {
      if ( null != value ) {
        return RubyString.newString(runtime, value, runtime.getEncodingService().getEncodingFromString("UTF-8"));
      } else {
        return null;
      }
    }

    public static String toJavaString (final RubyString value)
    {
      return value.toString();
    }

    public static URI newURI (final RubyString value) throws URISyntaxException
    {
      return new URI(value.toString());
    }

    public static URL newURL (final RubyString value) throws MalformedURLException
    {
      return new URL(value.toString());
    }

  };

  private Ruby mRuntime;

  public HTTPClient ()
  {
      mRuntime = Ruby.getDefaultInstance();
  }


  public Response head (final RubyString a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "HEAD"), a_url, a_headers, /* a_body */ (RubyString)null, a_expect, a_connection);
  }

  public Response get (final RubyString a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "GET"), a_url, a_headers, /* a_body */ (RubyString)null, a_expect, a_connection);
  }

  public Response delete (final RubyString a_url, final RubyHash a_headers, final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "DELETE"), a_url, a_headers, /* a_body */ (RubyString)null, a_expect, a_connection);
  }

  public Response post (final RubyString a_url, final RubyHash a_headers, final RubyString a_body,
                        final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "POST"), a_url, a_headers, a_body, a_expect, a_connection);
  }

  public Response put (final RubyString a_url, final RubyHash a_headers, final RubyString a_body,
                       final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "PUT"), a_url, a_headers, a_body, a_expect, a_connection);
  }

  public Response patch (final RubyString a_url, final RubyHash a_headers, final RubyString a_body,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "PATCH"), a_url, a_headers, a_body, a_expect, a_connection);
  }
 
  /*         */
  /* --- --- */
  /*/        */

  public Response get_to_file (final RubyString a_url, final RubyHash a_headers, final RubyString a_to,
                               final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception, URISyntaxException
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "GET"), a_url, a_headers, /* a_from */ (URI)null, JRubyHelper.newURI(a_to), a_expect, a_connection);
  }

  public Response post_to_file (final RubyString a_url, final RubyHash a_headers, final RubyString a_body, final RubyString a_to,
                                final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception, URISyntaxException
  {
    return _do_http(JRubyHelper.toRubyString(mRuntime, "POST"), a_url, a_headers,
        /* a_stream */ new InputStream(mRuntime, a_body), 
        new OutputStream(mRuntime, new URI("file://" + JRubyHelper.toJavaString(a_to))), 
        a_expect, a_connection
    );
  }


  /*         */
  /* --- --- */
  /*/        */

  /*
   * Perform an HTTP POST request to send a local file ( a_from ) to an url ( a_to ). 
   */
  public Response post_file (final RubyString a_from, final RubyString a_to, final RubyHash a_headers,
                             final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "POST"), /* a_url */ a_to, a_headers, JRubyHelper.newURI(a_from), a_expect, a_connection);
  }

  /*
   * Perform an HTTP PUT request to send a local file ( a_from ) to an url ( a_to ). 
   */
  public Response put_file (final RubyString a_from, final RubyString a_to, final RubyHash a_headers,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "PUT"), /* a_url */ a_to, a_headers, JRubyHelper.newURI(a_from), a_expect, a_connection);
  }

  /*
   * Perform an HTTP PATCH request to send a local file ( a_from ) to an url ( a_to ). 
   */
  public Response patch_file (final RubyString a_from, final RubyString a_to, final RubyHash a_headers,
                                     final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    return do_http(JRubyHelper.toRubyString(mRuntime, "PATCH"), /* a_url */ a_to, a_headers, JRubyHelper.newURI(a_from), a_expect, a_connection);
  }

  /*         */
  /* --- --- */
  /*/        */

  private Response do_http (final RubyString a_method, final RubyString a_url, final RubyHash a_headers, final RubyString a_body,
                            final Expect a_expect, final Connection a_connection)
    throws MalformedURLException, ProtocolException, IOException, Exception
    {
      return _do_http(a_method, a_url, a_headers, 
        new InputStream(mRuntime, a_body), 
        new OutputStream(mRuntime), 
        a_expect, a_connection
      );
  }

  private Response do_http (final RubyString a_method, final RubyString a_url, final RubyHash a_headers, final URI a_from,
                            final Expect a_expect, final Connection a_connection)
    throws MalformedURLException, ProtocolException, IOException, Exception
    {
      return _do_http(a_method, a_url, a_headers, 
        new InputStream(mRuntime, new URI("file://" + a_from.getPath())), 
        new OutputStream(mRuntime), 
        a_expect, a_connection
      );
  }
  

  private Response do_http (final RubyString a_method, final RubyString a_url, final RubyHash a_headers, final URI a_from, final URI a_to,
                            final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    if ( null != a_from ) {
      return _do_http(a_method, a_url, a_headers, 
        new InputStream(mRuntime, new URI("file://" + a_from.getPath())), 
        new OutputStream(mRuntime, new URI("file://" + a_to.getPath())),
        a_expect, a_connection
      );
    } else {
      return _do_http(a_method, a_url, a_headers, 
        /* a_stream */ (InputStream)null, 
        new OutputStream(mRuntime, new URI("file://" + a_to.getPath())), 
        a_expect, a_connection
      );
    }
  }

  /*         */
  /* --- --- */
  /*         */ 

  private static class Stream 
  {

    protected Ruby       mRuntime = null;
    protected RubyString data = null;
    protected URI        uri  = null;

    public Stream(final Ruby runtime, final RubyString data)
    {
      mRuntime  = runtime;
      this.data = data;
      this.uri  = null;
    }

    public Stream(final Ruby runtime, final URI uri)
    {
      mRuntime = runtime;
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

    public InputStream(final Ruby runtime, final RubyString data)
    {
      super(runtime, data);
    }

    public InputStream(final Ruby runtime, final URI uri)
    {
      super(runtime, uri);
    }

    public void write (HttpURLConnection a_connection)
      throws MalformedURLException, ProtocolException, IOException, Exception, FileNotFoundException
    {
      if ( null != data ) {
        new DataOutputStream(a_connection.getOutputStream()).write(data.getBytes());
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
        return data.getBytes().length;
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

    private FileOutputStream mStream = null;

    public OutputStream(final Ruby runtime)
    {
      super(runtime, JRubyHelper.toRubyString (runtime, ""));
      mStream = null;
    }

    public OutputStream(final Ruby runtime, final URI uri) 
      throws FileNotFoundException
    {
      super(runtime, uri);
      mStream = new FileOutputStream(uri.getPath());
    }

    public void write (final byte[] bytes, final int length, final RubyString contentType)
    throws Exception
    {
      if ( null != mStream ) {
        mStream.write(bytes, 0, length);
      } else {
         this.data.append(
          RubyString.newString(mRuntime, bytes, /* start */ 0, /* length */ length, /* encoding */ mRuntime.getEncodingService().getEncodingFromString("UTF-8"))
         );
      }
    }

    public final RubyString content ()
    {
      if ( null != uri ) {
        return JRubyHelper.toRubyString(mRuntime, uri.getPath());
      }
      return data;
    }

  };

  /*         */
  /* --- --- */
  /*/        */
  private Response _do_http (final RubyString a_method, final RubyString a_url, final RubyHash a_headers, final InputStream a_input_stream, final OutputStream a_output_stream,
                            final Expect a_expect, final Connection a_connection)
  throws MalformedURLException, ProtocolException, IOException, Exception
  {
    HttpURLConnection connection   = null;
    Response          response     = null;
    Exception         exception    = null;
    RubyString        responseBody = null;
    final String      method       = JRubyHelper.toJavaString(a_method);

    if ( true == DEBUG ) {
      System.out.println("[JAVA][DEBUG] ~> METHOD  - " + a_method);
      System.out.println("[JAVA][DEBUG] ~> URL     - " + a_url);
      if ( true == method.equals("POST") || true == method.equals("PUT") || true == method.equals("PATCH") ) {
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
      connection = (HttpURLConnection) JRubyHelper.newURL(a_url).openConnection();

      // ... set method and properties ...
      if ( true == method.equals("PATCH") ) {
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
          connection.setRequestMethod(JRubyHelper.toJavaString(a_method));
        }
      } else {
        // ... this set must be called here ! - do not move it !
        connection.setRequestMethod(JRubyHelper.toJavaString(a_method));
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
      if ( true == method.equals("POST") || true == method.equals("PUT") || true == method.equals("PATCH") ) {

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
      final int        responseCode        = connection.getResponseCode();
      final RubyString responseContentType = JRubyHelper.toRubyString(mRuntime, connection.getContentType());

      if ( true == DEBUG ) {
        System.out.println("[JAVA][DEBUG] - RX      - Status Code   : " + responseCode);
      }

      // ... set response ...
      if ( 204 == responseCode ) {
        // ... no body ...
        response = new Response(connection.getResponseCode(), responseBody, /* content */ null);
      } else {
        if ( true == DEBUG ) {
          System.out.println("[JAVA][DEBUG] - RX      - Content-Type  : " + responseContentType );
          System.out.println("[JAVA][DEBUG] - RX      - Content-Length: " + connection.getContentLengthLong());
        }
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
            JRubyHelper.toRubyString(mRuntime, connection.getContentType()), connection.getContentLengthLong()
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
