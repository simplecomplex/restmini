<?php
/**
 * @file
 * Contains \SimpleComplex\RestMini\Client.
 */

namespace SimpleComplex\RestMini;

/**
 * Small powerful REST client.
 */
class Client {

  /**
   * @var string
   */
  const CONFIG_DOMAIN = 'lib_simplecomplex_restmini_client';

  /**
   * Whether to SSL verify peer, when option ssl_verify not set.
   *
   * @var boolean
   */
  const SSL_VERIFY_DEFAULT = TRUE;

  /**
   * Default connect timeout in seconds, overridable by Drupal conf variable
   * 'contimeout'.
   *
   * @var integer
   */
  const CONNECT_TIMEOUT_DEFAULT = 5;

  /**
   * Default request timeout in seconds; overridable by Drupal conf variable
   * 'reqtimeout'.
   *
   * @var integer
   */
  const REQUEST_TIMEOUT_DEFAULT = 20;

  /**
   * Default (minimum) surplus PHP execution time to leave for script execution
   * after reception of response.
   * In seconds; overridable by Drupal conf variable 'surplusexectime'.
   *
   * @var integer
   */
  const SURPLUS_EXECTIME_DEFAULT = 5;

  /**
   * Default when no 'log_severity' option.
   *
   * @var string
   */
  const LOG_SEVERITY_DEFAULT = LOG_WARNING;

  /**
   * Default when no 'log_type' option.
   *
   * @var string
   */
  const LOG_TYPE_DEFAULT = 'restmini';

  /**
   * Response header separator.
   *
   * @var string
   */
  const RESPONSE_HEADER_SEP = ' | ';

  /**
   * Record same-named headers cumulative.
   *
   *  Values:
   *  - falsy: don't, record only last
   *  - 'rtl': right-to-left, last is first
   *  - any other value: left-to-right, last is last
   *
   * @var string
   */
  const RESPONSE_HEADER_CUMULATE = 'rtl';

  /**
   * @var integer
   */
  protected static $errorCodeOffset = 1500;

  /**
   * Actual numeric values may be affected by non-zero $errorCodeOffset
   * of classes extending Client.
   *
   * @see Client::$errorCodeOffset
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
   * @see Client::alterOptions()
   *
   * @var array
   */
  protected static $optionsSupported = array(
    'accept',
    'accept_charset',
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
    // Array; key => value, not 'key: value'.
    'headers',
    'get_headers',
    'log_severity',
    'log_type',
    'service_response_info_wrapper',
    'record_args',
    'logger',
  );

  /**
   * Record of last time (if any) a client postponed PHP execution timeout.
   *
   * @var integer
   */
  protected static $tExecTimeoutPostponed = 0;

  /**
   * Default request timeout resolved.
   *
   * @see Client::REQUEST_TIMEOUT_DEFAULT
   * @see Client::configGet()
   * @see Client::__construct()
   *
   * @var integer
   */
  protected static $requestTimeoutDefault = 0;

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
   * Last request arguments path+query+body, if option record_args.
   *
   * @var null|array
   */
  protected $argsRecorded;

  /**
   * Accept request header value, unless overridden by options[accept]
   * or (deprecated) options[headers][Accept].
   *
   * @var string
   */
  protected $accept = 'application/json, application/hal+json';

  /**
   * Accept request header value, unless overridden by options[accept_charset]
   * or (deprecated) options[headers][Accept-Charset].
   *
   * @var string
   */
  protected $acceptCharset = 'UTF-8';

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
   * Response 'stops'; number HTTP status lines recorded in response headers.
   *
   * @var integer
   */
  protected $stops = 0;

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
   * @see Client::alterOptions()
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
   *   Supported: see Client::alterOptions().
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

    // Get current request timeout default; we use it a lot.
    if (!static::$requestTimeoutDefault) {
      static::$requestTimeoutDefault = static::configGet('', 'reqtimeout', static::REQUEST_TIMEOUT_DEFAULT);
    }

    // Resolve options.
    $this->alterOptions($options);
  }

  /**
   * Convenience factory which facilitates chaining.
   *
   * @code
   * // Get JSON-decoded response.
   * $data = Client::make('http://server', '/endpoint')->get()->result();
   * // Check status first.
   * $request = Client::make('http://server', '/endpoint')->get();
   * if ($request->status() == 200) {
   *   $data = $request->result();
   * }
   * // Get all relevant properties in one go:
   * $response = Client::make('http://server', '/endpoint')->get()->result(TRUE);
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
   * $raw = Client::make('http://server', '/endpoint')->get()->raw():
   * @endcode
   *
   * @see Client::alterOptions()
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
   *   Supported: see Client::alterOptions().
   *   Default: empty.
   *
   * @return Client|static
   *   Client or extending type.
   */
  public static function make($server, $endpoint, $options = array()) {
    return new static($server, $endpoint, $options);
  }

  /**
   * Get list of names of options supported.
   *
   * @see Client::alterOptions()
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
   * $client = new Client('http://ser.ver', '/end-point');
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
   *   - (str) accept
   *   - (str) accept_charset
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
   *   - (int) log_severity: severity level when logging any error type except
   *     logical error and (runtime) configuration error
   *   - (string) log_type: use that log type when logging.
   *   - (bool) service_response_info_wrapper (tell service to wrap response
   *     in object listing service response properties)
   *   - (bool) record_args: make path+query+body args available
   *   - (obj) logger: PSR-3 logger; will be used directly or as logger for
   *       Inspect.
   *   Default: empty.
   * @param array $unset
   *   Non-empty: unset keys named like the values of this array.
   *   Default: empty.
   *
   * @return $this
   */
  public function alterOptions($set = array(), $unset = array()) {
    $options =& $this->options;

    if ($set) {
      $supported =& static::$optionsSupported;
      foreach ($set as $key => $val) {
        if (in_array($key, $supported)) {
          $options[$key] = $val;
          switch ($key) {
            case 'accept':
              $this->accept = $val;
              break;
            case 'accept_charset':
            case 'acceptCharset':
              $this->acceptCharset = $val;
              break;
          }
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

    // Get (deprecated) accept and accept charset set in headers.
    if (!empty($options['headers'])) {
      $deprecated = array();
      $opts_raw = NULL;
      if (!empty($options['headers']['Accept'])) {
        $this->accept = $options['headers']['Accept'];
        $opts_raw = $options;
        unset($options['headers']['Accept']);
        $options['accept'] = $this->accept;
        $deprecated[] = 'headers.Accept - accept';
      }
      if (!empty($options['headers']['Accept-Charset'])) {
        $this->acceptCharset = $options['headers']['Accept-Charset'];
        if (!$opts_raw) {
          $opts_raw = $options;
        }
        unset($options['headers']['Accept-Charset']);
        $options['accept_charset'] = $this->acceptCharset;
        $deprecated[] = 'headers.Accept-Charset - accept_charset';
      }
      if ($deprecated) {
        $this->log(
          LOG_NOTICE,
          'Deprecated headers option(s), use root option(s) instead; ' . join(', ', $deprecated),
          NULL,
          array(
            'options seen' => $opts_raw,
            'options fixed' => $options,
          )
        );
        unset($deprecated, $opts_raw);
      }
    }

    // Secure valid request body content type, or empty.
    // Request body content type is only required if POST|PUT, so we don't
    // require it to be set at all.
    if (!empty($options['content_type'])
      && $options['content_type'] != 'application/x-www-form-urlencoded'
      && strpos($options['content_type'], 'application/json') !== 0
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
      $options['connect_timeout'] = static::configGet('', 'contimeout', static::CONNECT_TIMEOUT_DEFAULT);
    }
    if (!$options || !array_key_exists('request_timeout', $options)) {
      $options['request_timeout'] = static::$requestTimeoutDefault;
    }
    // cUrl request timeout includes connection timeout, so effectively
    // request timeout cannot be less than connect timeout.
    if ($options['request_timeout'] <= $options['connect_timeout']) {
      $options['request_timeout'] = $options['connect_timeout'] + 1;
    }

    // Resolve SSL issues.
    if ($this->ssl) {
      // Set 'ssl_verify' option, if not set.
      if (!array_key_exists('ssl_verify', $options)) {
        // Turned off by variable setting? Otherwise use current class default.
        $options['ssl_verify'] = static::configGet('', 'sslverifydefnot', FALSE) ? FALSE : static::SSL_VERIFY_DEFAULT;
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

    // log_severity must be integer; RFC-5424.
    if (isset($options['log_severity'])) {
      if (!ctype_digit($options['log_severity']) || $options['log_severity'] < 0 || $options['log_severity'] > 7) {
        $this->error = array(
          'code' => static::errorCode('option_value_invalid'),
          'name' => 'option_value_invalid',
          'message' => $em = 'Option \'log_severity\' value must be an integer 7 thru 0',
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
        // Use class constant default.
        unset($options['log_severity']);
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
   * @see Client::make()
   *
   * @param array|NULL $pathArgs
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-arg/second-path-arg
   *   Default: empty.
   * @param array|NULL $queryArgs
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=arg&second=arg
   *   Default: empty.
   *
   * @return $this
   */
  public function head($pathArgs = NULL, $queryArgs = NULL) {
    return $this->request('HEAD', $pathArgs, $queryArgs);
  }

  /**
   * Send HTTP GET request, for index or retrieve operation.
   *
   * Chainable, returns self.
   *
   * @see Client::make()
   *
   * @param array|NULL $pathArgs
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-arg/second-path-arg
   *   Default: empty.
   * @param array|NULL $queryArgs
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=arg&second=arg
   *   Default: empty.
   *
   * @return $this.
   */
  public function get($pathArgs = NULL, $queryArgs = NULL) {
    return $this->request('GET', $pathArgs, $queryArgs);
  }

  /**
   * Send HTTP POST request, for create operation.
   *
   * Chainable, returns self.
   *
   * @see Client::make()
   *
   * @param array|NULL $pathArgs
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-arg/second-path-arg
   *   Default: empty.
   * @param array|NULL $queryArgs
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=arg&second=arg
   *   Default: empty.
   * @param array|NULL $bodyArgs
   *   Default: empty.
   *
   * @return $this
   */
  public function post($pathArgs = NULL, $queryArgs = NULL, $bodyArgs = NULL) {
    return $this->request('POST', $pathArgs, $queryArgs, $bodyArgs);
  }

  /**
   * Send HTTP PUT request, for update operation.
   *
   * Chainable, returns self.
   *
   * @see Client::make()
   *
   * @param array|NULL $pathArgs
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-arg/second-path-arg
   *   Default: empty.
   * @param array|NULL $queryArgs
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=arg&second=arg
   *   Default: empty.
   * @param array|NULL $bodyArgs
   *   Default: empty.
   *
   * @return $this
   */
  public function put($pathArgs = NULL, $queryArgs = NULL, $bodyArgs = NULL) {
    return $this->request('PUT', $pathArgs, $queryArgs, $bodyArgs);
  }

  /**
   * Send HTTP DELETE request, for remove or delete operation.
   *
   * Chainable, returns self.
   *
   * @see Client::make()
   *
   * @param array|NULL $pathArgs
   *   Each bucket will be added to the server + endpoint URL.
   *   Example: http://ser.ver/end-point/first-path-arg/second-path-arg
   *   Default: empty.
   * @param array|NULL $queryArgs
   *   Each key-value pair becomes key=value.
   *   Example: http://ser.ver/end-point?first=arg&second=arg
   *   Default: empty.
   *
   * @return $this
   */
  public function delete($pathArgs = NULL, $queryArgs = NULL) {
    return $this->request('DELETE', $pathArgs, $queryArgs);
  }

  /**
   * Resets instance vars that may get populated upon request.
   *
   * @see Client::make()
   *
   * @param $method
   *   GET ~ index|retrieve (default).
   *   POST ~ create.
   *   PUT ~ update.
   *   DELETE.
   * @param array|NULL $pathArgs
   *   Default: empty.
   * @param array|NULL $queryArgs
   *   Default: empty.
   * @param array|NULL $bodyArgs
   *   Ignored unless $method is POST or PUT.
   *   Default: empty.
   *
   * @return $this
   */
  public function request($method = 'GET', $pathArgs = NULL, $queryArgs = NULL, $bodyArgs = NULL) {
    // Check for previous error, like empty constructor arg $server.
    if ($this->error) {
      return $this;
    }

    // Reset instance.
    $this->reset();

    $this->url = $this->server . $this->endpointAdjust();

    // Options.
    $options =& $this->options;

    $record_args = FALSE;
    if (!empty($options['record_args'])) {
      $record_args = TRUE;
      $this->argsRecorded = array();
    }

    // Path args: double URL encoding of some chars,
    // to prevent parsing errors.
    // A slash in a path arg could otherwise be interpreted
    // as two path fragments instead of one (Drupal url-decodes full url
    // before parsing into path fragments and query args).
    if ($pathArgs) {
      foreach ($pathArgs as $val) {
        $this->url .= '/' . rawurlencode(str_replace(array('/', '?', '&', '='), array('%2F', '3F', '26', '3D'), $val));
      }
      if ($record_args) {
        $this->argsRecorded['path'] =& $pathArgs;
      }
    }

    // Query arguments: single URL encoding.
    if ($queryArgs) {
      $i = -1;
      foreach ($queryArgs as $key => $val) {
        // Only ?-delimiter if first arg and (empty endpoint
        // or endpoint doesn't contain ?).
        $this->url .= (!(++$i) && (!$this->endpoint || !strpos($this->endpoint, '?')) ? '?' : '&')
          . $key . '=' . rawurlencode($val);
      }
      if ($record_args) {
        $this->argsRecorded['query'] =& $queryArgs;
      }
    }

    // Basic cURL options.
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

    // Handle long request timeout; make sure PHP doesn't time out
    // before cURL does.
    // Only if any max_execution_time at all (is zero in CLI mode).
    if ($options['request_timeout'] > static::$requestTimeoutDefault
      && ($envTimeout = ini_get('max_execution_time'))
    ) {
      // We cannot know if/when anybody else postponed execution timeout,
      // but at least keep track of own postponal(s).
      $tLastPostponed = static::$tExecTimeoutPostponed;
      $elapsed = time() - (!$tLastPostponed ? (int) $_SERVER['REQUEST_TIME'] : $tLastPostponed);
      $remaining = (int) $envTimeout - $elapsed;
      $needed = $options['request_timeout'] + static::configGet('', 'surplusexectime', static::SURPLUS_EXECTIME_DEFAULT);
      if ($remaining < $needed) {
        static::$tExecTimeoutPostponed = time();
        set_time_limit($needed);
      }
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
          $caFile = static::certificateDir() . '/' . $caFile;
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
    $headers = array(
      'Accept: ' . $this->accept,
      'Accept-Charset: ' . $this->acceptCharset,
    );
    if (!empty($options['headers'])) {
      // Copy, because we may add header(s), per request.
      $hdrs =& $options['headers'];
      foreach ($hdrs as $key => $val) {
        $headers[] = $key . ': ' . $val;
      }
      unset($hdrs);
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
        if ($bodyArgs) {
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
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = http_build_query($bodyArgs));
          }
          else {
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = json_encode($bodyArgs));
          }
          if ($record_args) {
            $this->argsRecorded['body'] =& $bodyArgs;
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
        if ($bodyArgs) {
          // Making a server look for POST (body) vars when HTTP method is PUT
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
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = http_build_query($bodyArgs));
          }
          else {
            $headers[] = 'Content-Length: ' . strlen($curlOpts[CURLOPT_POSTFIELDS] = json_encode($bodyArgs));
          }
          if ($record_args) {
            $this->argsRecorded['body'] =& $bodyArgs;
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
            'method' => $method,
            'options' => $options,
            'path args' => $pathArgs,
            'query args' => $queryArgs,
            'body args' => $bodyArgs,
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
        isset($this->options['log_severity']) ? $this->options['log_severity'] : static::LOG_SEVERITY_DEFAULT,
        'Failed to initiate connection',
        NULL,
        $this->info('request') + ($record_args ? array() : array(
          'args' => array(
            'path' => $pathArgs,
            'query' => $queryArgs,
            'body' => $bodyArgs,
          )
        ))
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
        isset($this->options['log_severity']) ? $this->options['log_severity'] : static::LOG_SEVERITY_DEFAULT,
        'Failed to set request options',
        NULL,
        $this->info('request') + ($record_args ? array() : array(
          'args' => array(
            'path' => $pathArgs,
            'query' => $queryArgs,
            'body' => $bodyArgs,
          )
        )) + array(
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

    // Clean up response headers.
    if (static::RESPONSE_HEADER_CUMULATE && $this->stops < 2 && !empty($options['get_headers'])) {
      $rspHdrs =& $this->responseHeaders;
      $hdrKys = array_keys($rspHdrs);
      $remHdrs = array();
      foreach ($hdrKys as $hdr) {
        if (strpos($hdr, 'cumulative_') === 0) {
          $remHdrs[] = $hdr;
        }
      }
      if ($remHdrs) {
        foreach ($remHdrs as $hdr) {
          unset($rspHdrs[$hdr]);
        }
      }
      unset($rspHdrs, $hdrKys, $remHdrs);
    }

    // Check response.
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
        isset($this->options['log_severity']) ? $this->options['log_severity'] : static::LOG_SEVERITY_DEFAULT,
        $em,
        NULL,
        $this->info() + ($record_args ? array() : array(
          'args' => array(
            'path' => $pathArgs,
            'query' => $queryArgs,
            'body' => $bodyArgs,
          )
        )) + array(
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
        isset($this->options['log_severity']) ? $this->options['log_severity'] : static::LOG_SEVERITY_DEFAULT,
        'Response error status code ' . $this->status,
        NULL,
        $this->info() + ($record_args ? array() : array(
          'args' => array(
            'path' => $pathArgs,
            'query' => $queryArgs,
            'body' => $bodyArgs,
          )
        ))
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
   *  Request properties:
   *  - method (also returned when truthy arg $response)
   *  - url (also returned when truthy arg $response)
   *  - server
   *  - endpoint
   *  - options
   *  - accept
   *  - accept_chars
   *
   *  Response properties:
   *  - parser (but not returned when truthy arg $response)
   *  - status
   *  - content_type
   *  - content_length
   *  - headers
   *  - stops (zero unless option get_headers)
   *  - started
   *  - duration
   *  - error
   *
   * @param string $only
   *   Values: request|response.
   *   Default: empty; expose info of request and response.
   *
   * @return array
   */
  public function info($only = '') {
    $what = 3;
    if ($only) {
      $what = $only == 'request' ? 1 : 2;
    }
    if ($what == 2) {
      $request = array();
    }
    else {
      $request = array(
        'server' => $this->server,
        'endpoint' => $this->endpoint,
        'options' => $this->options,
        'accept' => $this->accept,
        'accept_chars' => $this->acceptCharset,
        'parser' => $this->parser,
      );
      if ($what == 1) {
        $request['error'] = $this->error;
      }
      if ($this->started && !empty($this->options['record_args'])) {
        $request['args'] = $this->argsRecorded;
      }
    }
    if ($what == 1) {
      $response = array();
    }
    else {
      $response = array(
        'status' => $this->status,
        'content_type' => $this->contentType,
        'content_length' => $this->contentLength,
        'headers' => $this->responseHeaders,
        'stops' => $this->stops,
        'started' => $this->started,
        'duration' => $this->duration,
        'error' => $this->error,
      );
    }

    return $request + $response;
  }

  /**
   * @return string
   */
  public function __toString() {
    $s = get_class($this) . '(';
    $info = $this->info();
    $first = TRUE;
    foreach ($info as $k => $v) {
      if ($first) {
        $first = FALSE;
      }
      else {
        $s .= ', ';
      }
      $s .= $k . ':' . $v;
    }

    return $s . ')';
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
   * $get_result_key = Client::make('http://server', '/endpoint')->get()->result(array('remote', 'server', 'wraps', 'my', 'data'));
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
      return !$responseInfo ? FALSE : (
        $this->info('response') + array(
          'result' => FALSE,
        )
      );
    }

    // Empty.
    if ($this->response == '') {
      return !$responseInfo ? '' : (
        $this->info('response') + array(
          'result' => '',
        )
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
      return !$responseInfo ? NULL : (
        $this->info('response') + array(
          'result' => NULL,
        )
      );
    }

    // Parse.
    $data = $this->parse();
    // Parse error.
    if ($data === $this->parser['error']) {
      $this->log(
        isset($this->options['log_severity']) ? $this->options['log_severity'] : static::LOG_SEVERITY_DEFAULT,
        'Failed to parse response',
        NULL,
        get_object_vars($this)
      );
      $this->error = array(
        'code' => static::errorCode('response_parse'),
        'name' => 'response_parse',
        'message' => 'Failed to parse response',
      );
      return !$responseInfo ? NULL : (
        $this->info('response') + array(
          'result' => NULL,
        )
      );
    }

    if (!$fetchKeyPath) {
      return !$responseInfo ? $data : (
        $this->info('response') + array(
          'result' => $data,
        )
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
   * @return $this
   */
  public function reset() {
    $this->error = array();
    $this->method = '';
    $this->url = '';
    $this->argsRecorded = NULL;
    $this->started = 0;
    $this->duration = 0;
    $this->responseHeaders = array();
    $this->stops = 0;
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
   * @see Client::request()
   *
   * @return string
   */
  protected function endpointAdjust() {
    return $this->endpoint;
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
   * Get config var.
   *
   * This implementation attempts to get from server environment variables.
   *
   * Beware that environment variables are always strings.
   *
   *  Server environment variable names used:
   *  - lib_simplecomplex_restmini_client_contimeout
   *  - lib_simplecomplex_restmini_client_reqtimeout
   *  - lib_simplecomplex_restmini_client_surplusexectime
   *  - lib_simplecomplex_restmini_client_sslverifydefnot
   *  - lib_simplecomplex_restmini_client_cacertssrc
   *  - lib_simplecomplex_restmini_client_cacertsdir
   *
   * @param string $domain
   *   Default: static::CONFIG_DOMAIN.
   * @param string $name
   * @param mixed $default
   *   Default: NULL.
   *
   * @return mixed
   *   String, unless no such var and arg default isn't string.
   */
  protected static function configGet($domain, $name, $default = NULL) {
    return ($val = getenv(($domain ? $domain : static::CONFIG_DOMAIN) . '_' . $name)) !== FALSE ? $val : $default;
  }

  /**
   * @param string $str
   *
   * @return string
   */
  protected static function plaintext($str) {
    return htmlspecialchars(strip_tags($str), ENT_QUOTES, 'UTF-8');
  }

  /**
   * Get default certificates dir.
   *
   * @return string
   */
  protected static function certificateDir() {
    return static::configGet('', 'cacertsdir', '/etc/ssl/certs');
  }

  /**
   * Uses optional PSR-3 logger and/or Inspect if applicable.
   *
   * @param integer $severity
   * @param string $message
   * @param \Exception|NULL $exception
   *   Ignored if no Inspect library.
   * @param mixed $variable
   *   Ignored if no Inspect library.
   *   Ignored if truthy arg $exception.
   */
  protected function log($severity, $message, $exception = NULL, $variable = NULL) {
    static $inspect = -1, $logger;
    // Check for Inspect, and whether this object was initialized with a PSR-3
    // logger (as option).
    if ($inspect == -1) {
      // This implementation expects the Inspect library source to be placed
      // right beside this source (Composer would place it there).
      if (file_exists(dirname(__FILE__) . '/../../inspect/src/Inspect.php')) {
        include_once dirname(__FILE__) . '/../../inspect/src/Inspect.php';
        $inspect = 1;
      }
      else {
        $inspect = 0;
      }
      // Use PSR-3 logger; directly or as logger for Inspect.
      if (!empty($this->options['logger'])) {
        $logger = $this->options['logger'];
        if (!is_object($logger) || !method_exists($logger, 'log')) {
          $logger = NULL;
        }
      }
    }
    if ($inspect) {
      $opts = array(
        'type' => !empty($this->options['log_type']) ? $this->options['log_type'] : static::LOG_TYPE_DEFAULT,
        'message' => $message,
        'severity' => $severity,
        'wrappers' => 1,
      );
      if ($logger) {
        $opts['logger'] = $logger;
      }
      // Trace exception, or inspect variable.
      if ($exception) {
        \SimpleComplex\Inspect\Inspect::trace($exception, $opts);
      }
      else {
        \SimpleComplex\Inspect\Inspect::log($variable, $opts);
      }
    }
    else {
      if ($exception) {
        $message .= ': (' . $exception->getCode() . ') ' . $exception->getMessage()
          . ' @' . $exception->getFile() . ':' . $exception->getLine();
      }
      if ($logger) {
        $logger->log($severity, $message);
      }
      else {
        error_log($message);
      }
    }
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
      $cumulate = static::RESPONSE_HEADER_CUMULATE;
      $headers =& $this->responseHeaders;
      // HTTP status text(s).
      if (strpos($line, 'HTTP') === 0 && ($pos = strpos($line, ' ')) && ctype_digit(substr($line, $pos + 1, 3))) {
        $val = substr($line, $pos + 1);
        // Register 100 Continue status.
        if ($val == '100 Continue') {
          $headers['initial_status'] = '100 Continue';
        }
        else {
          ++$this->stops;
          // Status text must be without status code.
          $headers['status_text'] = substr($val, 4);
          if ($cumulate) {
            if (isset($headers['cumulative_status'])) {
              if ($cumulate != 'rtl') {
                $headers['cumulative_status'] .= static::RESPONSE_HEADER_SEP . $val;
              }
              else {
                $headers['cumulative_status'] = $val . static::RESPONSE_HEADER_SEP . $headers['cumulative_status'];
              }
            }
            else {
              $headers['cumulative_status'] = $val;
            }
          }
        }
      }
      // Straight 'key: value' headers. If dupes, the values must be
      // concatenated as comma-separated list.
      elseif (($pos = strpos($line, ': '))) {
        $name = substr($line, 0, $pos);
        $val = substr($line, $pos + 2);
        $headers[$name] = $val;
        if ($cumulate) {
          $cumulate_name = 'cumulative_' . $name;
          if (isset($headers[$cumulate_name])) {
            if ($cumulate != 'rtl') {
              $headers[$cumulate_name] .= static::RESPONSE_HEADER_SEP . $val;
            }
            else {
              $headers[$cumulate_name] = $val . static::RESPONSE_HEADER_SEP . $headers[$cumulate_name];
            }
          }
          else {
            $headers[$cumulate_name] = $val;
          }
        }
      }
      // Wrongish header, which isn't 'key: value'.
      else {
        $headers[] = $line;
      }
    }
    // Satisfy return value contract with PHP cUrl.
    return strlen($headerLine);
  }

}
