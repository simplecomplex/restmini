<?php
/**
 * SimpleComplex PHP RestMini Client
 * @link      https://github.com/simplecomplex/restmini
 * @copyright Copyright (c) 2017 Jacob Friis Mathiasen
 * @license   https://github.com/simplecomplex/restmini/blob/master/LICENSE (MIT License)
 */
declare(strict_types=1);

namespace SimpleComplex\RestMini;

/**
 * Convenience class - defaults to parse JSON object to array.
 */
class ClientParseAssoc extends Client
{
    /**
     * Defaults to parse JSON object to associative array.
     *
     * @var array
     */
    protected $parser = [
        // 'this' means client instance self.
        'object' => 'this',
        'method' => 'parseJson',
        // To associative arrays (default).
        'options' => true,
        // Return value on error.
        'error' => null,
    ];
}
