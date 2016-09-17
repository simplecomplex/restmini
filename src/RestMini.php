<?php
/**
 * @file
 * Contains \SimpleComplex\RestMini\RestMini.
 */

namespace SimpleComplex\RestMini;

/**
 * Small powerful REST client.
 */
class RestMini {

  /**
   * Whether to SSL verify peer, when option ssl_verify not set.
   *
   * @var boolean
   */
  const SSL_VERIFY_DEFAULT = TRUE;


  /**
   * Default connect timeout in seconds, overridable by Drupal conf variable
   * 'restmini_client_contimeout'.
   *
   * @var integer
   */
  const CONNECT_TIMEOUT_DEFAULT = 5;

  /**
   * Default request timeout in seconds; overridable by Drupal conf variable
   * 'restmini_client_reqtimeout'.
   *
   * @var integer
   */
  const REQUEST_TIMEOUT_DEFAULT = 20;

  /**
   * @var integer
   */
  protected static $errorCodeOffset = 1500;

  /**
   * Actual numeric values may be affected by non-zero $errorCodeOffset
   * classes extending RestMini.
   *
   * @see RestMini::$errorCodeOffset
   *
   * @var array $errorCodes
   */
  protected static $errorCodes = array(
    'unknown' => 1,
    'server_arg_empty' => 31,
    'protocol_not_supported' => 32,
    'method_not_supported' => 35,
    'option_not_supported' => 36,
    'option_value_missing' => 37,
    'option_value_empty' => 38,
    'option_value_invalid' => 39,
    'init_connection' => 41,
    'request_options' => 42,
    'parser_not_callable' => 49,
    'response_false' => 51,

    // cURL equivalents.
    'url_malformed' => 52,
    'host_not_found' => 53,
    'connection_failed' => 54,
    'request_timed_out' => 55,
    'too_many_redirects' => 56,

    // cURL equivalents.
    'ssl_client_certificate' => 61,
    'ssl_bad_cipher' => 62,
    'ssl_self_signed' => 63,
    'ssl_cacertfile_notpem' => 64,
    'ssl_cacertfile_missing' => 65,
    'ssl_cacertfile_empty' => 66,
    'ssl_cacertfile_bad' => 67,

    'content_type_mismatch' => 71,
    'response_parse' => 72,
    'keypath_not_found' => 75,
    'response_error' => 81,
  );

  /**
   * @see RestMini::alterOptions()
   *
   * @var array
   */
  protected static $optionsSupported = array(
    'content_type',
    'connect_timeout',
    'request_timeout',
    'ssl_verify',
    'ssl_cacert_file',
    'status_vain_result_void',
    'ignore_status',
    'ignore_content_type',
    'auth',
    'user',
    'pass',
    'headers',
    'get_headers',
    'log_severity_error',
    'service_response_info_wrapper',
    'logger',
  );

  /**
   *  If error, buckets are:
   *  - (int) code
   *  - (str) name
   *  - (str) message
   *
   * @var array
   */
  protected $error = array();

  /**
   * @var string
   */
  protected $server = '';

  /**
   * @var string
   */
  protected $endpoint = '';

  /**
   * @var array
   */
  protected $options = array();

  /**
   * @var boolean|NULL
   */
  protected $ssl;

  /**
   * Last request method.
   *
   * @var string
   */
  protected $method = '';

  /**
   * Last requested url.
   *
   * @var string
   */
  protected $url = '';

  /**
   * Accept request header value, unless overridden by options[headers][Accept].
   *
   * @var string
   */
  protected $accept = 'application/json, application/hal+json';

  /**
   * @var array
   */
  protected $parser = array(
    // 'this' means client instance self.
    'object' => 'this',
    'method' => 'parseJson',
    // Associative arrays.
    'options' => TRUE,
    // Return value on error.
    'error' => NULL,
  );

  /**
   * Timestamp of request start.
   *
   * @var integer
   */
  protected $started = 0;

  /**
   * Request duration, in seconds.
   *
   * @var integer
   */
  protected $duration = 0;

  /**
   * @var array
   */
  protected $responseHeaders = array();

  /**
   * @var integer
   */
  protected $status = 0;

  /**
   * Response Content-Type header evaluates to NULL if none sent.
   *
   * @var string|NULL
   */
  protected $contentType;

  /**
   * Evaluated content (byte) length, not response header Content-Length.
   *
   * @var integer
   */
  protected $contentLength = 0;

  /**
   * @var mixed
   */
  protected $response;

  /**
   * @see RestMini::alterOptions()
   *
   * @param string $server
   *   Protocol + domain (~ http://ser.ver).
   *   Prepends http:// if no protocol (only http and https supported).
   *   Trailing slash will be removed.
   * @param string $endpoint
   *   Examples: 'path', '/base/route/end-point', '/endpoint.php',
   *   '/dir/endpoint.aspx?arg=val'.
   *   Leading slash is optional; will be prepended if missing.
   *   Default: empty.
   * @param array $options
   *   Supported: see RestMini::alterOptions().
   *   Default: empty.
   */
  public function __construct($server, $endpoint = '', $options = array()) {
    if (!$server) {
      $this->error = array(
        'code' => static::errorCode('server_arg_empty'),
        'name' => 'server_arg_empty',
        'message' => $em = 'Constructor arg server is empty',
      );
      $this->log(
        LOG_ERR,
        $em,
        NULL,
        array(
          'server' => $server,
          'endpoint' => $endpoint,
          'options' => $options,
        )
      );

      return;
    }

    // Check if SSL.
    if (strpos($server, 'https://') === 0) {
      $this->ssl = TRUE;
    }
    // Prepend default protocol, if none.
    elseif (strpos($server, 'http://') === FALSE) {
      if (strpos($server, ':/') !== FALSE) {
        $this->error = array(
          'code' => static::errorCode('protocol_not_supported'),
          'name' => 'protocol_not_supported',
          'message' => $em = 'Constructor arg server protocol not supported',
        );
        $this->log(
          LOG_ERR,
          $em,
          NULL,
          array(
            'server' => $server,
            'endpoint' => $endpoint,
            'options' => $options,
          )
        );
        return;
      }
      $server = 'http://' . $server;
    }

    // Remove trailing slash.
    if ($server{strlen($server) - 1} === '/') {
      $server = substr($server, 0, strlen($server) - 1);
    }
    $this->server = $server;

    // Endpoint may be anything from '/restmini_endpoint'
    // to 'dir/non_restmini_endpoint.aspx?arg=val'.
    if ($endpoint !== '') {
      // Secure leading slash.
      $this->endpoint = ($endpoint{0} == '/' ? '' : '/') . $endpoint;
    }

    // Resolve options.
    $this->alterOptions($options);
  }

  /**
   * Convenience factory which facilitates chaining.
   *
   * @code
   * // Get JSON-decoded response.
   * $data = RestMini::make('http://server', '/endpoint')->get()->result();
   * // Check status first.
   * $request = RestMini::make('http://server', '/endpoint')->get();
   * if ($request->status() == 200) {
   *   $data = $request->result();
   * }
   * // Get all relevant properties in one go:
   * $response = RestMini::make('http://server', '/endpoint')->get()->result(TRUE);
   * if ($response['status'] == 200) {
   *   // Use $response['result'] ...
   * }
   * elseif (!empty($response['headers']['Some header')) {
   *   // ...
   * }
   * elseif ($response['error']) {
   *   // ...
   * }
   * // Get raw response.
   * $raw = RestMini::make('http://server', '/endpoint')->get()->raw():
   * @endcode
   *
   * @see RestMini::alterOptions()
   *
   * @param string $server
   *   Protocol + domain (~ http://ser.ver).
   *   Prepends http:// if no protocol (only http and https supported).
   *   Trailing slash will be removed.
   * @param string $endpoint
   *   Examples: 'path', '/base/route/end-point', '/endpoint.php',
   *   '/dir/endpoint.aspx?arg=val'.
   *   Leading slash is optional; will be prepended if missing.
   *   Default: empty.
   * @param array $options
   *   Supported: see RestMini::alterOptions().
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public static function make($server, $endpoint, $options = array()) {
    return new static($server, $endpoint, $options);
  }

  /**
   * Get list of names of options supported.
   *
   * @see RestMini::alterOptions()
   *
   * @return array
   */
  public static function optionsSupported() {
    return static::$optionsSupported;
  }

  /**
   * Set and/or remove options.
   *
   * Aborts, and sets client in error state, if a key of the $set arg
   * isn't supported.
   *
   * Chainable, returns self.
   *
   * If removing connect_timeout or request_timeout: they will be set again
   * to module defaults.
   *
   * @code
   * $client = new RestMini('http://ser.ver', '/end-point');
   * // First request, get index.
   * $list = $client->get();
   * // ...
   * // Second request, update a record - but first change some options.
   * $client->alterOptions(
   *   // Set.
   *   array(
   *     'get_headers' => TRUE,
   *   ),
   *   // Remove.
   *   array(
   *     'connect_timeout',
   *     'request_timeout',
   *   ),
   * )->put(
   *   array(21),
   *   NULL,
   *   array('title' => 'Changed record')
   * );
   * @endcode
   *
   * @param array $set
   *   Supported:
   *   - (str) content_type (of request body; supported:
   *     ''|'application/x-www-form-urlencoded'|'application/json[; charset=some-charset]')
   *   - (int) connect_timeout
   *   - (int) request_timeout
   *   - (bool) ssl_verify
   *   - (str) ssl_cacert_file (use custom CA cert file instead the common file)
   *   - (bool) status_vain_result_void (~ result() returns empty string if
   *     status >=300; suppress error messages etc. received in response body)
   *   - (bool) ignore_status (~ don't trust response status code;
   *     like 200 might actually be 404)
   *   - (bool) ignore_content_type (~ don't trust response content type;
   *     HTML might actually be JSON, and vice versa)
   *   - (str) auth (supported: 'basic' and 'ntlm')
   *   - (str) user (for [username]:[password])
   *   - (str) pass (for [username]:[password])
   *   - (arr) headers
   *   - (bool) get_headers
   *   - (int) log_severity_error: use that severity level when logging errors.
   *   - (bool) service_response_info_wrapper (tell service to wrap response
   *     in object listing service response properties)
   *   - (obj) logger: PSR-3 logger
   *   Default: empty.
   * @param array $unset
   *   Non-empty: unset keys named like the values of this array.
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function alterOptions($set = array(), $unset = array()) {
    $options =& $this->options;

    if ($set) {
      $supported =& static::$optionsSupported;
      foreach ($set as $key => $val) {
        if (in_array($key, $supported)) {
          $options[$key] = $val;
        }
        else {
          $this->error = array(
            'code' => static::errorCode('option_not_supported'),
            'name' => 'option_not_supported',
            'message' => $em = 'Option[' . static::plaintext($key) . '] not supported.',
          );
          $this->log(
            LOG_ERR,
            $em,
            NULL,
            $set
          );

          return $this;
        }
      }
    }
    if ($unset) {
      foreach ($unset as $val) {
        unset($options[$val]);
      }
    }

    // Secure valid request body content type, or empty.
    // Request body content type is only required if POST|PUT, so we don't
    // require it to be set at all.
    if (!empty($options['content_type'])
      && $options['content_type'] != 'application/x-www-form-urlencoded'
      && strpos($options['content_type'], 'application/json') === FALSE
    ) {
      $this->error = array(
        'code' => static::errorCode('option_value_invalid'),
        'name' => 'option_value_invalid',
        'message' => $em = 'Option \'content_type\' value invalid, must be empty or application/x-www-form-urlencoded or start with application/json',
      );
      $this->log(
        LOG_ERR,
        $em,
        NULL,
        array(
          'options' => $options,
          'set' => $set,
          'unset' => $unset,
        )
      );
    }

    // Secure timeout options.
    if (!$options || !array_key_exists('connect_timeout', $options)) {
      $options['connect_timeout'] = static::configGet('restmini', 'contimeout', static::CONNECT_TIMEOUT_DEFAULT);
    }
    if (!$options || !array_key_exists('request_timeout', $options)) {
      $options['request_timeout'] = static::configGet('restmini', 'reqtimeout', static::REQUEST_TIMEOUT_DEFAULT);
    }

    // Resolve SSL issues.
    if ($this->ssl) {
      // Set 'ssl_verify' option, if not set.
      if (!array_key_exists('ssl_verify', $options)) {
        // Turned off by variable setting? Otherwise use current class default.
        $options['ssl_verify'] = static::configGet('restmini', 'sslverifydefnot', FALSE) ? FALSE : static::SSL_VERIFY_DEFAULT;
      }
      // Secure CA certs file.
      if ($options['ssl_verify']) {
        // Use default SSL CA certs bundle file, unless custom specified.
        if (empty($options['ssl_cacert_file'])) {
          $options['ssl_cacert_file'] = 'cacert.pem';
        }
      }
    }

    // user:pass.
    if (!empty($options['user'])) {
      if (empty($options['pass'])) {
        $em = 'Option \'user\' set and non-empty, but option \'pass\' ';
        if (!array_key_exists('pass', $options)) {
          $this->error = array(
            'code' => static::errorCode('option_value_missing'),
            'name' => 'option_value_missing',
            'message' => $em .= 'not set.',
          );
        }
        else {
          $this->error = array(
            'code' => static::errorCode('option_value_empty'),
            'name' => 'option_value_empty',
            'message' => $em .= 'empty.',
          );
        }
        $this->log(
          LOG_ERR,
          $em,
          NULL,
          array(
            'options' => $options,
            'set' => $set,
            'unset' => $unset,
          )
        );

        return $this;
      }
      if (empty($options['auth'])) {
        $options['auth'] = 'basic';
      }
      else {
        switch ('' . $options['auth']) {
          case 'basic':
          case 'ntlm':
            break;
          default:
            $this->error = array(
              'code' => static::errorCode('option_value_invalid'),
              'name' => 'option_value_invalid',
              'message' => $em = 'Option \'auth\' value invalid',
            );
            $this->log(
              LOG_ERR,
              $em,
              NULL,
              array(
                'options' => $options,
                'set' => $set,
                'unset' => $unset,
              )
            );
        }
      }
    }

    return $this;
  }

  /**
   * Set response parser.
   *
   * Chainable, returns self.
   *
   * @param object|string $object
   *   String 'this' resolves to client instance self.
   * @param string $method
   * @param mixed $options
   *   Gets passed as second arg to the parser method, unless null.
   * @param null|boolean $errorReturn
   *   Return value of parser when failing.
   *
   * @return $this
   */
  public function parser($object, $method, $options = NULL, $errorReturn = NULL) {
    $isCallable = TRUE;
    $obj = $object;
    if ($obj === 'this') {
      $obj = $this;
    }
    elseif (!is_object($object)) {
      $isCallable = FALSE;
      $this->log(
        LOG_ERR,
        'Parser not callable, arg object not object',
        NULL,
        func_get_args()
      );
    }
    if ($isCallable && !method_exists($obj, $method)) {
      $isCallable = FALSE;
      $this->log(
        LOG_ERR,
        'Parser not callable, arg object has no such method',
        NULL,
        func_get_args()
      );
    }
    if (!$isCallable) {
      $this->error = array(
        'code' => static::errorCode('parser_not_callable'),
        'name' => 'parser_not_callable',
        'message' => 'Parser not callable',
      );
    }
    else {
      $this->parser = array(
        $object,
        $method,
        $options,
        $errorReturn,
      );
    }

    return $this;
  }

  /**
   * Send HTTP HEAD request, as content-less alternative to GET.
   *
   * Chainable, returns self.
   *
   * @see RestMini::make()
   *
   * @param array|NULL $pathParams
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-param/second-path-param
   *   Default: empty.
   * @param array|NULL $queryParams
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=param&second=param
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function head($pathParams = NULL, $queryParams = NULL) {
    return $this->request('HEAD', $pathParams, $queryParams);
  }

  /**
   * Send HTTP GET request, for index or retrieve operation.
   *
   * Chainable, returns self.
   *
   * @see RestMini::make()
   *
   * @param array|NULL $pathParams
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-param/second-path-param
   *   Default: empty.
   * @param array|NULL $queryParams
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=param&second=param
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function get($pathParams = NULL, $queryParams = NULL) {
    return $this->request('GET', $pathParams, $queryParams);
  }

  /**
   * Send HTTP POST request, for create operation.
   *
   * Chainable, returns self.
   *
   * @see RestMini::make()
   *
   * @param array|NULL $pathParams
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-param/second-path-param
   *   Default: empty.
   * @param array|NULL $queryParams
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=param&second=param
   *   Default: empty.
   * @param array|NULL $bodyParams
   *   Ignored unless $method is POST or PUT.
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function post($pathParams = NULL, $queryParams = NULL, $bodyParams = NULL) {
    return $this->request('POST', $pathParams, $queryParams, $bodyParams);
  }

  /**
   * Send HTTP PUT request, for update operation.
   *
   * Chainable, returns self.
   *
   * @see RestMini::make()
   *
   * @param array|NULL $pathParams
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-param/second-path-param
   *   Default: empty.
   * @param array|NULL $queryParams
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=param&second=param
   *   Default: empty.
   * @param array|NULL $bodyParams
   *   Ignored unless $method is POST or PUT.
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function put($pathParams = NULL, $queryParams = NULL, $bodyParams = NULL) {
    return $this->request('PUT', $pathParams, $queryParams, $bodyParams);
  }

  /**
   * Send HTTP DELETE request, for remove or delete operation.
   *
   * Chainable, returns self.
   *
   * @see RestMini::make()
   *
   * @param array|NULL $pathParams
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-param/second-path-param
   *   Default: empty.
   * @param array|NULL $queryParams
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=param&second=param
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function delete($pathParams = NULL, $queryParams = NULL) {
    return $this->request('DELETE', $pathParams, $queryParams);
  }

  /**
   * Resets instance vars that may get populated upon request.
   *
   * @param $method
   *   GET ~ index|retrieve (default).
   *   POST ~ create.
   *   PUT ~ update.
   *   DELETE.
   * @param array|NULL $pathParams
   *   Default: empty.
   * @param array|NULL $queryParams
   *   Default: empty.
   * @param array|NULL $bodyParams
   *   Ignored unless $method is POST or PUT.
   *   Default: empty.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function request($method = 'GET', $pathParams = NULL, $queryParams = NULL, $bodyParams = NULL) {
    // Check for previous error, like empty constructor arg $server.
    if ($this->error) {
      return $this;
    }

    // Reset instance.
    $this->reset();

    $this->url = $this->server . $this->endpointAdjust();

    // Path parameters: double URL encoding of some chars,
    // to prevent parsing errors.
    // A slash in a path parameter could otherwise be interpreted
    // as two path fragments instead of one (Drupal url-decodes full url
    // before parsing into path fragments and get parameters).
    if ($pathParams) {
      foreach ($pathParams as $val) {
        $this->url .= '/' . rawurlencode(str_replace(array('/', '?', '&', '='), array('%2F', '3F', '26', '3D'), $val));
      }
    }

    // Query parameters: single URL encoding.
    if ($queryParams) {
      $i = -1;
      foreach ($queryParams as $key => $val) {
        // Only ?-delimiter if first param and (empty endpoint
        // or endpoint doesn't contain ?).
        $this->url .= (!(++$i) && (!$this->endpoint || !strpos($this->endpoint, '?')) ? '?' : '&')
          . $key . '=' . rawurlencode($val);
      }
    }

    // Options.
    $options =& $this->options;
    $curlOpts = array(
      // Don't include header in output.
      CURLOPT_HEADER => FALSE,
      // Get response as string, don't echo it.
      CURLOPT_RETURNTRANSFER => TRUE,
      // Follow redirects.
      CURLOPT_FOLLOWLOCATION => TRUE,
      // Timeouts.
      CURLOPT_CONNECTTIMEOUT => $options['connect_timeout'],
      CURLOPT_TIMEOUT => $options['request_timeout'],
    );

    // Handle long request timeout; make sure PHP doesn't timeout
    // before cURL does.
    if (($requestTimeout = $options['request_timeout']) > static::REQUEST_TIMEOUT_DEFAULT
      // Only if any max_execution_time at all (is zero in drush/CLI mode).
      && ($envTimeout = ini_get('max_execution_time'))
      // Add 10%; PHP's timeout have to be more than cURL's.
      && ($requestTimeout = (int)ceil($requestTimeout * 1.1)) > $envTimeout
    ) {
      set_time_limit($requestTimeout);
    }

    // Getting response header comes with a performance price tag,
    // so we only do it on demand.
    if (!empty($options['get_headers'])) {
      $curlOpts[CURLOPT_HEADERFUNCTION] = array($this, 'responseHeaderCallback');
    }

    // SSL.
    $caFile = '';
    if ($this->ssl) {
      // Don't verify SSL certificate?
      if (!$options['ssl_verify']) {
        $curlOpts[CURLOPT_SSL_VERIFYPEER] = FALSE;
      }
      else {
        // Use CA cert bundle file (or custom cert file).
        $caFile = $options['ssl_cacert_file'];
        // Unless path+file (custom ssl_cacert_file option using path+file
        // instead of just file), prepend path.
        if (!strpos(' ' . $caFile, '/')) {
          $caFile = static::configGet('restmini', 'cacertsdir', '/etc/ssl/certs') . '/' . $caFile;
        }
        $curlOpts[CURLOPT_CAINFO] = $caFile;
      }
    }

    // user:pass?
    if (!empty($options['auth'])) {
      if ($options['auth'] == 'ntlm') {
        $curlOpts[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
        $curlOpts[CURLOPT_HTTPAUTH] = CURLAUTH_NTLM;
      }
      $curlOpts[CURLOPT_USERPWD] = $options['user'] . ':' . $options['pass'];
    }

    // Headers.
    if (empty($options['headers'])) {
      $headers = array(
        'Accept: ' . $this->accept,
        'Accept-Charset: UTF-8',
      );
    }
    else {
      // Copy, because we may add header(s), per request.
      $headers = $options['headers'];
      $headersConcat = array();
      foreach ($headers as $key => $val) {
        $headersConcat[] = $key . ': ' . $val;
      }
      if (empty($headers['Accept'])) {
        $headersConcat[] = 'Accept: ' . $this->accept;
      }
      if (empty($headers['Accept-Charset'])) {
        $headersConcat[] = 'Accept-Charset: UTF-8';
      }
      $headers =& $headersConcat;
    }
    if (!empty($options['service_response_info_wrapper'])) {
      // Custom header which tells RESTmini Service to wrap payload
      // in response info object.
      $headers[] = 'X-Rest-Service-Response-Info-Wrapper: 1';
    }

    // http method.
    switch ($method) {
      case 'HEAD':
        $curlOpts[CURLOPT_CUSTOMREQUEST] = 'HEAD';
        break;
      case 'GET':
        break;
      case 'POST':
        $curlOpts[CURLOPT_POST] = TRUE;
        if ($bodyParams) {
          // Resolve request body content type.
          $contentTypeJson = FALSE;
          // Default content type of the payload is x-www-form-urlencoded.
          if (empty($options['content_type'])) {
            $options['content_type'] = 'application/x-www-form-urlencoded';
          }
          elseif (strpos($options['content_type'], 'application/json') === 0) {
            $contentTypeJson = TRUE;
          }
          $headers[] = 'Content-Type: ' . $options['content_type'];
          if (!$contentTypeJson) {
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = http_build_query($bodyParams));
          }
          else {
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = json_encode($bodyParams));
          }
        }
        else {
          // Prevent 413 Request Entity Too Large error; Apache responds
          // like that when POST and no content length header.
          $headers[] = 'Content-Length: 0';
        }
        break;
      case 'PUT':
        $curlOpts[CURLOPT_CUSTOMREQUEST] = 'PUT';
        // CURLOPT_PUT is no good, because it makes cUrl
        // send 'Tranfer-Encoding: chunked'.
        // And 'chunked' is only useful when sending files, not 'form data'.
        if ($bodyParams) {
          // Making a server look for POST vars when HTTP method is PUT
          // may be real hard.
          $headers[] = 'X-HTTP-Method-Override: PUT';
          // Resolve request body content type.
          $contentTypeJson = FALSE;
          if (empty($options['content_type'])) {
            $options['content_type'] = 'application/x-www-form-urlencoded';
          }
          elseif (strpos($options['content_type'], 'application/json') === 0) {
            $contentTypeJson = TRUE;
          }
          $headers[] = 'Content-Type: ' . $options['content_type'];
          if (!$contentTypeJson) {
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = http_build_query($bodyParams));
          }
          else {
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = json_encode($bodyParams));
          }
        }
        else {
          $headers[] = 'Content-Length: 0';
        }
        break;
      case 'DELETE':
        $curlOpts[CURLOPT_CUSTOMREQUEST] = 'DELETE';
        break;
      default:
        $this->log(
          LOG_ERR,
          'Unsupported HTTP method',
          NULL,
          array(
            'server' => $this->server,
            'endpoint' => $this->endpoint,
            'options' => $options,
            'method' => $method,
            'path params' => $pathParams,
            'query params' => $queryParams,
            'body params' => $bodyParams,
            'url' => $this->url,
          )
        );
        $this->error = array(
          'code' => static::errorCode('method_not_supported'),
          'name' => 'method_not_supported',
          'message' => 'Unsupported HTTP method',
        );

        return $this;
    }
    $this->method = $method;

    $curlOpts[CURLOPT_HTTPHEADER] =& $headers;

    // cUrl begin.
    $resource = curl_init($this->url);
    $this->started = time();

    if ($resource === FALSE) {
      $this->error = array(
        'code' => static::errorCode('init_connection'),
        'name' => 'init_connection',
        'message' => 'Failed to initiate connection',
      );
      $this->log(
        isset($this->options['log_severity_error']) ? $this->options['log_severity_error'] : LOG_ERR,
        'Failed to initiate connection',
        NULL,
        array(
          'server' => $this->server,
          'endpoint' => $this->endpoint,
          'options' => $options,
          'method' => $method,
          'path params' => $pathParams,
          'query params' => $queryParams,
          'body params' => $bodyParams,
          'url' => $this->url,
          'error' => $this->error,
        )
      );

      return $this;
    }

    // Set options.
    if (!curl_setopt_array($resource, $curlOpts)) {
      $this->error = array(
        'code' => static::errorCode('request_options'),
        'name' => 'request_options',
        'message' => 'Failed to set request options',
      );
      $this->log(
        isset($this->options['log_severity_error']) ? $this->options['log_severity_error'] : LOG_ERR,
        'Failed to set request options',
        NULL,
        array(
          'server' => $this->server,
          'endpoint' => $this->endpoint,
          'options' => $options,
          'method' => $method,
          'path params' => $pathParams,
          'query params' => $queryParams,
          'body params' => $bodyParams,
          'url' => $this->url,
          'error' => $this->error,
          'curl info' => curl_getinfo($resource),
        )
      );
      curl_close($resource);

      return $this;
    }
    unset($curlOpts);

    // Send request.
    $this->response = curl_exec($resource);
    $this->duration = time() - $this->started;

    // Get status code.
    $this->status = curl_getinfo($resource, CURLINFO_HTTP_CODE);
    // Content type may be NULL (none), or FALSE (empty),
    // and it may contain character set (~ text/html; charset=utf-8).
    if (($contentType = curl_getinfo($resource, CURLINFO_CONTENT_TYPE))) {
      // Remove ; charset=.
      if (($pos = strpos($contentType, ';'))) {
        $contentType = substr($contentType, 0, $pos);
      }
    }
    else {
      $contentType = NULL;
    }
    $this->contentType = $contentType;

    if ($this->response === FALSE) {
      $cUrlErrorCode = curl_errno($resource);
      $cUrlErrorString = static::plaintext(str_replace("\n", ' ', curl_error($resource)));
      $em = $cUrlErrorString . ' (' . $cUrlErrorCode . ')';
      // Common error have dedicated error codes.
      switch ($cUrlErrorCode) {
        case CURLE_URL_MALFORMAT:
          $errorName = 'url_malformed';
          break;
        case CURLE_COULDNT_RESOLVE_HOST:
          $errorName = 'host_not_found';
          break;
        case CURLE_COULDNT_CONNECT:
          $errorName = 'connection_failed';
          break;
        case CURLE_OPERATION_TIMEOUTED:
          $errorName = 'request_timed_out';
          break;
        case CURLE_TOO_MANY_REDIRECTS:
          $errorName = 'too_many_redirects';
          break;
        case CURLE_SSL_CERTPROBLEM:
          // When sending a certificate. Something that this module
          // doesn't support.
          $errorName = 'ssl_client_certificate';
          break;
        case CURLE_SSL_CIPHER:
          $errorName = 'ssl_bad_cipher';
          break;
        case CURLE_SSL_CACERT:
          $errorName = 'ssl_self_signed';
          break;
        case 77: // CURLE_SSL_CACERT_BADFILE; not defined in PHP (>5.4?).
          if (!preg_match('/\.pem$/', $caFile)) {
            $errorName = 'ssl_cacertfile_notpem';
          }
          elseif (!file_exists($caFile)) {
            $errorName = 'ssl_cacertfile_missing';
          }
          elseif (!file_get_contents($caFile)) {
            $errorName = 'ssl_cacertfile_empty';
          }
          else {
            $errorName = 'ssl_cacertfile_bad';
          }
          break;
        default:
          $errorName = 'response_false';
      }
      $this->error = array(
        'code' => static::errorCode($errorName),
        'name' => $errorName,
        'message' => $em,
      );
      $this->log(
        isset($this->options['log_severity_error']) ? $this->options['log_severity_error'] : LOG_ERR,
        $em,
        //. ((!$this->ssl || (array_key_exists('ssl_verify', $options) && !$options['ssl_verify'])) ? '' : ', check ssl_verify'),
        NULL,
        array(
          'status' => $this->status,
          'response headers' => $this->responseHeaders,
          'server' => $this->server,
          'endpoint' => $this->endpoint,
          'options' => $options,
          'method' => $method,
          'path params' => $pathParams,
          'query params' => $queryParams,
          'body params' => $bodyParams,
          'url' => $this->url,
          'error' => $this->error,
          'curl error code' => $cUrlErrorCode,
          'curl error message' => $cUrlErrorString,
          'curl info' => curl_getinfo($resource),
        )
      );
      curl_close($resource);

      return $this;
    }
    // ...else: Response must be string, because of CURLOPT_RETURNTRANSFER.
    $this->response = trim($this->response);
    $this->contentLength = strlen($this->response);

    curl_close($resource);

    // Check for error status.
    if ($this->status >= 500) {
      $this->error = array(
        'code' => static::errorCode('response_error'),
        'name' => 'response_error',
        'message' => 'Response error',
      );
      $this->log(
        isset($this->options['log_severity_error']) ? $this->options['log_severity_error'] : LOG_ERR,
        'Response error status code ' . $this->status,
        NULL,
        array(
          'status' => $this->status,
          'response headers' => $this->responseHeaders,
          'content_type' => $this->contentType,
          'content_length' => $this->contentLength,
          'server' => $this->server,
          'endpoint' => $this->endpoint,
          'options' => $options,
          'method' => $method,
          'path params' => $pathParams,
          'query params' => $queryParams,
          'body params' => $bodyParams,
          'url' => $this->url,
          'error' => $this->error,
        )
      );
    }

    return $this;
  }

  /**
   * Last requested URL.
   *
   * @return string
   *   Empty: no last request, or current request failed before actual sending.
   */
  public function url() {
    return $this->url;
  }

  /**
   * Empty unless request has been sent, and failed.
   *
   *  If error, buckets are:
   *  - (int) code
   *  - (str) name
   *  - (str) message
   *
   * @return array
   */
  public function error() {
    return $this->error;
  }

  /**
   * HTTP response status.
   *
   * @return integer
   *   Zero: request not started, or request failed.
   */
  public function status() {
    return $this->status;
  }

  /**
   * Response headers.
   *
   * @return array()
   *   Empty unless last request used the 'get_headers' option.
   */
  public function headers() {
    return $this->responseHeaders;
  }

  /**
   * Get all info about the client and it's last request (if any).
   *
   *  Properties:
   *  - server
   *  - endpoint
   *  - options
   *  - method
   *  - status
   *  - content_type
   *  - content_length
   *  - headers
   *  - url
   *  - duration
   *  - error
   *
   * @return array
   */
  public function info() {
    return array(
      'server' => $this->server,
      'endpoint' => $this->endpoint,
      'options' => $this->options,
      'method' => $this->method,
      // Buckets like result() response info:
      'status' => $this->status,
      'content_type' => $this->contentType,
      'content_length' => $this->contentLength,
      'headers' => $this->responseHeaders,
      'url' => $this->url,
      'duration' => $this->duration,
      'error' => $this->error,
    );
  }

  /**
   * Get raw response.
   *
   * @return string|boolean|NULL
   *   NULL: request not started.
   *   FALSE: request failed.
   */
  public function raw() {
    return $this->response;
  }

  /**
   * Parsed response, or array of most properties of the response.
   *
   * If $fetchKeyPath, and it doesn't match: returns the whole parsed response.
   *
   *  Returned wrapper array buckets when $responseInfo:
   *  - (int) status
   *  - (str|null) content_type
   *  - (int) content_length
   *  - (arr) headers
   *  - (mixed) result
   *  - (arr) error
   *
   * @code
   * $get_result_key = RestMini::make('http://server', '/endpoint')->get()->result(array('remote', 'server', 'wraps', 'my', 'data'));
   * @endcode
   *
   * @param array $fetchKeyPath
   *   List of keys to recurse by to find the actual payload data.
   *   Default: empty.
   * @param boolean $responseInfo
   *   Ignored if $fetchKeyPath, unless error; then response info may be useful.
   *   Truthy: get all properties of the response.
   *   Default: FALSE (~ get result only).
   *
   * @return mixed
   *   NULL: request not started, or failed to parse response.
   *   FALSE: request failed, or actual parsed response.
   *   Empty string: empty response.
   */
  public function result($fetchKeyPath = array(), $responseInfo = FALSE) {
    if ($this->error) {
      return !$responseInfo ? FALSE : array(
        'status' => $this->status,
        'content_type' => $this->contentType,
        'content_length' => $this->contentLength,
        'headers' => $this->responseHeaders,
        'url' => $this->url,
        'duration' => $this->duration,
        'result' => FALSE,
        'error' => $this->error,
      );
    }

    // Empty.
    if ($this->response == '') {
      return !$responseInfo ? '' : array(
        'status' => $this->status,
        'content_type' => $this->contentType,
        'content_length' => $this->contentLength,
        'headers' => $this->responseHeaders,
        'url' => $this->url,
        'duration' => $this->duration,
        'result' => '',
        'error' => array(),
      );
    }

    // Get out if status indicates no usable content,
    // and option 'status_vain_result_void' set and truthy.
    if (!$responseInfo && $this->status >= 300 && !empty($this->options['status_vain_result_void'])) {
      return '';
    }

    // Detect HTML if we don't want that - lots of services return HTML
    // as fallback when erring.
    $parse = TRUE;
    if (!empty($this->options['ignore_content_type'])) {
      if ($this->response{0} === '<'
        // text/xml|application/xml.
        && !strpos($this->accept, 'xml')
        // text/html.
        && !strpos($this->accept, 'html')
      ) {
        $parse = FALSE;
      }
    }
    elseif (strpos($this->accept, $this->contentType) === FALSE) {
      $parse = FALSE;
    }
    if (!$parse) {
      $this->error = array(
        'code' => static::errorCode('content_type_mismatch'),
        'name' => 'content_type_mismatch',
        'message' => 'Response content type doesnt match parser',
      );
      return !$responseInfo ? NULL : array(
        'status' => $this->status,
        'content_type' => $this->contentType,
        'content_length' => $this->contentLength,
        'headers' => $this->responseHeaders,
        'url' => $this->url,
        'duration' => $this->duration,
        'error' => $this->error,
        'result' => NULL,
      );
    }

    // Parse.
    $data = $this->parse();
    // Parse error.
    if ($data === $this->parser['error']) {
      $this->log(
        isset($this->options['log_severity_error']) ? $this->options['log_severity_error'] : LOG_ERR,
        'Failed to parse response',
        NULL,
        get_object_vars($this)
      );
      $this->error = array(
        'code' => static::errorCode('response_parse'),
        'name' => 'response_parse',
        'message' => 'Failed to parse response',
      );
      return !$responseInfo ? NULL : array(
        'status' => $this->status,
        'content_type' => $this->contentType,
        'content_length' => $this->contentLength,
        'headers' => $this->responseHeaders,
        'url' => $this->url,
        'duration' => $this->duration,
        'error' => $this->error,
        'result' => NULL,
      );
    }

    if (!$fetchKeyPath) {
      return !$responseInfo ? $data : array(
        'status' => $this->status,
        'content_type' => $this->contentType,
        'content_length' => $this->contentLength,
        'headers' => $this->responseHeaders,
        'url' => $this->url,
        'duration' => $this->duration,
        'result' => $data,
        'error' => array(),
      );
    }

    // Copy the whole data set in case the keypath doesn't match.
    $orig = $data;
    // Recurse.
    foreach ($fetchKeyPath as $key) {
      if ($data && is_array($data) && array_key_exists($key, $data)) {
        $data = $data[$key];
      }
      else {
        // No match, return all.
        $this->error = array(
          'code' => static::errorCode('keypath_not_found'),
          'name' => 'keypath_not_found',
          'message' => 'Result key-path not found in result data',
        );
        return $orig;
      }
    }
    return $data;
  }

  /**
   * Resets all response properties that may waste memory space.
   *
   * Chainable, returns self.
   *
   * Does not reset parser properties.
   *
   * No need to call this method prior to a new request;
   * the get|post|put|delete() methods call it automatically.
   *
   * @return RestMini
   *   Or extending type.
   */
  public function reset() {
    $this->error = array();
    $this->method = '';
    $this->url = '';
    $this->started = 0;
    $this->duration = 0;
    $this->responseHeaders = array();
    $this->status = 0;
    $this->contentType = NULL;
    $this->contentLength = 0;
    $this->response = NULL;

    return $this;
  }

  /**
   * Attempts to parse response body using the buckets of instance parser.
   *
   * @return mixed
   */
  protected function parse() {
    $parser = $this->parser;
    $object = $parser['object'];
    if ($object === 'this') {
      $object = $this;
    }
    $method = $parser['method'];

    return $parser['options'] === NULL ? $object->$method($this->response) :
      $object->$method($this->response, $parser['options']);
  }

  /**
   * Parses JSON.
   *
   * @param string $response
   * @param boolean $assoc
   *   True: objects will be converted to associative arrays.
   *   Default: false. However, this class' instance parser defaults to true.
   * @return mixed
   *   Null on error.
   */
  public function parseJson($response, $assoc = FALSE) {
    return json_decode($response, $assoc);
  }

  /**
   * Adjust endpoint before sending request.
   *
   * Mustn't change instance var endpoint, must only return that
   * or an adjusted version of it.
   *
   * Meant to be overridden in extending class.
   *
   * @see RestMini::request()
   *
   * @return string
   */
  protected function endpointAdjust() {
    return $this->endpoint;
  }

  /**
   * CURLOPT_HEADERFUNCTION implementation.
   *
   * @param resource $resource
   * @param string $headerLine
   * @return integer
   *   Header line byte length.
   */
  protected function responseHeaderCallback($resource, $headerLine) {
    // Remove trailing \r\n.
    if (($line = trim($headerLine))) {
      // Find HTTP status text; once. If multiple status texts (considered an
      // error) the first will rule; the later will be ignored as such.
      if (!isset($this->responseHeaders['status_text']) && strpos($line, 'HTTP') === 0) {
        // Register 100 Continue status.
        if (strpos($line, '100 Continue')) {
          $this->responseHeaders['initial_status'] = '100 Continue';
        }
        elseif (strpos($line, ' OK') == strlen($line) - 3) {
          $this->responseHeaders['status_text'] = 'OK';
        }
        else {
          $this->responseHeaders['status_text'] = preg_replace('/^HTTPS?\/\d\.\d+ \d+ (.+)$/', '$1', $line);
        }
      }
      // Straight 'key: value' headers. If dupes, the values must be
      // concatenated as comma-separated list.
      elseif (($pos = strpos($line, ': '))) {
        $name = substr($line, 0, $pos);
        if (!isset($this->responseHeaders[$name])) {
          $this->responseHeaders[$name] = substr($line, $pos + 2);
        }
        else {
          $this->responseHeaders[$name] .= ', ' . substr($line, $pos + 2);
        }
      }
      // Wrongish header, which isn't 'key: value'.
      // If multiple status texts, all but the first will go here.
      else {
        $this->responseHeaders[] = $line;
      }
    }
    // Satisfy return value contract with PHP cUrl.
    return strlen($headerLine);
  }

  /**
   * Get error code by name, or code list, or code range.
   *
   * @param string $name
   *   Non-empty: return code by name (defaults to 'unknown')
   *   Default: empty (~ return codes list).
   * @param boolean $range
   *   TRUE: return code range array(N-first, N-last).
   *   Default: FALSE (~ ignore argument).
   *
   * @return integer|array
   */
  public static function errorCode($name = '', $range = FALSE) {
    static $codes;

    if ($name) {
      return static::$errorCodeOffset
      + (array_key_exists($name, static::$errorCodes) ? static::$errorCodes[$name] : static::$errorCodes['unknown']);
    }

    if ($range) {
      return array(
        static::$errorCodeOffset,
        // Range of sub modules should only be 100, to allow for all sub modules
        // within an overall range of 1000.
        static::$errorCodeOffset + 99
      );
    }

    if (!$codes) {
      $codes = static::$errorCodes; // Copy.
      if (($offset = static::$errorCodeOffset)) {
        foreach ($codes as &$code) {
          $code += $offset;
        }
        unset($code); // Iteration ref.
      }
    }

    return $codes;
  }

  /**
   * Traces Exception, if $exception and SimpleComplex\Inspect\Inspect exists.
   *
   * @param integer $severity
   * @param string $message
   * @param \Exception|NULL $exception
   * @param mixed $variable
   */
  protected function log($severity, $message, $exception = NULL, $variable = NULL) {
    static $inspect = -1, $logger;
    if ($inspect == -1) {
      $filename = dirname(__FILE__) . '/../../inspect/src/Inspect.php';
      if (file_exists($filename)) {
        include_once dirname(__FILE__) . '/../../inspect/src/Inspect.php';
        $inspect = 1;
      }
      else {
        $inspect = 0;
      }
      if (!empty($this->options['logger']) && is_object($logger) && method_exists($logger, 'log')) {
        $logger = $this->options['logger'];
      }
    }
    if ($inspect) {
      $opts = array(
        'type' => 'restmini',
        'message' => $message,
        'severity' => $severity,
        'wrappers' => 1,
      );
      if ($logger) {
        $opts['logger'] = $logger;
      }
      if ($exception) {
        \SimpleComplex\Inspect\Inspect::trace($exception, $opts);
      }
      else {
        \SimpleComplex\Inspect\Inspect::log($variable, $opts);
      }
    }
    elseif ($logger) {
      $logger->log($severity, $message);
    }
    else {
      error_log($message);
    }
  }

  /**
   * Get config var.
   *
   * This implementation attempts to get from server environment variables.
   * And it only supports the domain 'restmini'.
   *
   *  Server environment variable names used:
   *  - lib_simplecomplex_restmini_contimeout
   *  - lib_simplecomplex_restmini_reqtimeout
   *  - lib_simplecomplex_restmini_sslverifydefnot
   *  - lib_simplecomplex_restmini_cacertssrc
   *  - lib_simplecomplex_restmini_cacertsdir
   *
   * @param string $domain
   * @param string $name
   * @param mixed $default
   *   Default: NULL.
   *
   * @return mixed
   */
  protected static function configGet($domain, $name, $default = NULL) {
    // Environment vars.
    return ($val = getenv('lib_simplecomplex_restmini_' . $name)) !== FALSE ? $val : $default;
  }

  /**
   * @param string $str
   *
   * @return string
   */
  protected static function plaintext($str) {
    return htmlspecialchars(strip_tags($str), ENT_QUOTES, 'UTF-8');
  }

}
