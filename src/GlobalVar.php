<?php 
/**
 * This file is part of Cooker Mail package
 *
 * (c) Cooker <thinklang0917@gmail.com>
 *
 */

namespace Cooker\Mail;

/**
 *  GlobalVar is a container for key/value pairs.
 *  
 *   @author Cooker <thinklang0917@gmail.com>
 */

class GlobalVar 
{



    public static function setVars(array $vars = array())
    {
        self::$vars = $vars;
    }

    public static function all()
    {
        return self::$vars;
    }

    public static function keys()
    {
        return array_keys(self::$vars);
    }

    public static function add(array $vars = array())
    {
        self::$vars = array_replace(self::$vars, $vars);
    }

    public static function get($key, $default = null)
    {
        $key  = array_filter(explode('.', $key));
        $coun = count($key);
        $res  = null;
        switch($coun){
        case 1: 
             $res = array_key_exists($key[0], self::$vars) ? self::$vars[$key[0]] : $default; 
             break;
        case 2:
            $res = isset(self::$vars[$key[0]][$key[1]]) && self::$vars[$key[0]][$key[1]]
                ? self::$vars[$key[0]][$key[1]]
                : $default;
            break;
        }
        return $res;
    }

    public static function set($key, $value)
    {
        self::$vars[$key] = $value;
    }

    public static function has($key)
    {
        return array_key_exists($key, self::$vars);
    }

    public static function remove($key)
    {
        unset(self::$vars[$key]);
    }

    public static function getDigits($key, $default = '')
    {
        // we need to remove - and + because they're allowed in the filter
        return str_replace(array('-', '+'), '', self::filter($key, $default, FILTER_SANITIZE_NUMBER_INT));
    }

    public static function getInt($key, $default = 0)
    {
        return (int) self::get($key, $default);
    }

    public static function getBoolean($key, $default = false)
    {
        return self::filter($key, $default, FILTER_VALIDATE_BOOLEAN);
    }

    public static function filter($key, $default = null, $filter = FILTER_DEFAULT, $options = array())
    {
        $value = self::get($key, $default);
        // Always turn $options into an array - this allows filter_var option shortcuts.
        if (!is_array($options) && $options) {
            $options = array('flags' => $options);
        }
        // Add a convenience check for arrays.
        if (is_array($value) && !isset($options['flags'])) {
            $options['flags'] = FILTER_REQUIRE_ARRAY;
        }
        return filter_var($value, $filter, $options);
    }

    protected static $vars = array(
        'imap_default_host' => 'localhost',    
        'imap_default_port' => 143,
        'imap_auth_type'    => 'CHECK', 
        'imap_conn_options' => null,
        'imap_timeout'      => 5,
        'imap_auth_cid'     => null,
        'imap_auth_pwd'     => null,
        'imap_delimiter'    => null,
        'imap_vendor'       => null,
        'imap_ns_personal'  => null,
        'imap_ns_shared'    => null,
        'imap_ns_other'     => null,
        'imap_force_caps'   => false,
        'imap_force_lsub'   => false,
        'imap_force_ns'     => false,
        'imap_skip_hide_folders' => false,
        'imap_dual_use_folders'  => null,
        'imap_disabled_caps'     => null,



        'smtp_default_host' => 'localhost',
    
    
    
    
    );


}
