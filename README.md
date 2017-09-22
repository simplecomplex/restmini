## RestMini Client ##

### What ###

Simple HTTP client with chainable methods.
 
Highly configurable, and extensive error handling and logging.

### Example ###

```php
use SimpleComplex\RestMini\Client;

// Get JSON-decoded response data.
$data = Client::make('http://server', '/endpoint', [
    'headers' => [
        'X-Whatever' => 'Hello',
    ],
    'json_parse_assoc' => true,
])->get(
    [
        'some-path-arg' => 'foo',
    ],
    [
        'some-query-arg' => 'bar',
    ]
)->result();

// Check status first.
$response = Client::make('http://server', '/endpoint')->get();
if ($response->status() == 200) {
    $data = $response->result();
}
else {
    $info = $response->info();
    $container = \SimpleComplex\Utils\Dependency::container();
    $container->get('logger')->warning("Darned:\n" . json_encode($info, JSON_PRETTY_PRINT));
}

// Get raw response data.
$raw = Client::make('http://server', '/endpoint')->get()->raw():
```

### Client options ###

- (obj) **logger**: PSR-3 logger; otherwise checks in Utils\Dependency.
- (bool) **parse_json_assoc**: parse objects to associative arrays;  
     ignored if using the parser() method
- (str) **accept**
- (str) **accept_charset**
- (str) **content_type**: of request body; default application/json; supported:  
     ''|application/json[; charset=some-charset]|application/x-www-form-urlencoded
- (int) **connect_timeout**: default 5 (seconds);  
     class constant CONNECT_TIMEOUT_DEFAULT
- (int) **request_timeout**
- (bool) **ssl_verify**: default true;  
     class constant SSL_VERIFY_DEFAULT
- (str) **ssl_cacert_file**: use custom CA cert file instead the common file
- (bool) **status_vain_result_void**: ~ result() returns empty string if  
     status >=300; suppress error messages etc. received in response body
- (bool) **ignore_status**: ~ don't trust response status code;  
     like 200 might actually be 404
- (bool) **ignore_content_type**: ~ don't trust response content type;  
     HTML might actually be JSON, and vice versa
- (str) **auth**: 'basic' or 'ntlm'; defaults to 'basic' if option _user_
- (str) **user**: for auth
- (str) **pass**: for auth
- (arr) **headers**: request headers
- (bool) **get_headers**: get response headers
- (int) **log_severity**: severity level when logging any error type except  
     logical error and (runtime) configuration error; default warning;  
     class constant LOG_SEVERITY_DEFAULT
- (string) **log_type**: use that log type when logging; default 'restmini_client';  
     class constant LOG_TYPE_DEFAULT
- (bool) **service_response_info_wrapper**: tell service to wrap response  
     in object listing service response properties
- (bool) **record_args**: make path+query+body args available after request

### Requirements ###

- PHP >=7.0
- PHP cURL extension
- [PSR-3 Log](https://github.com/php-fig/log)
- [SimpleComplex Inspect](https://github.com/simplecomplex/inspect)
- [SimpleComplex Utils](https://github.com/simplecomplex/php-utils)
