<?php 
namespace Cooker\Mail;

class Helper
{
    /**
     * parse socket options 
     *
     * @access public  static 
     * @param  $options array 
     * @param  $host    string
     *
     * @return array 
     */

    public static function parseSocketOptions($options = array(), $host = '')
    {
        if (empty($host) || empty($options)) {
            return $options;
        }
        $hostUrl = parse_url($host);
        $host    = isset($hostUrl['host']) ? $hostUrl['host'] : $host;

        if (array_key_exists($host, $options)) {
            $options = $options[$host];
        }
        return $options;
    }

    /**
     * escape a string when it contains special char (RFC3501) 
     *
     * @access public 
     * @param  string $string 
     * @param  bool  $forceQuotes 
     * @return escaped string 
     */

    public static function escape($string, $forceQuotes = false)
    {
        if(is_null($string)){
            return 'NIL';
        }elseif($string === ''){
            return '""';
        }   
        if (!$forceQuotes && !preg_match('/[\x00-\x20\x22\x25\x28-\x2A\x5B-\x5D\x7B\x7D\x80-\xFF]/', $string)) {
            return $string;
        }

        // quoted-string
        if (!preg_match('/[\r\n\x00\x80-\xFF]/', $string)) {
            return '"' . addcslashes($string, '\\"') . '"';
        }

        // literal-string
        return sprintf("{%d}\r\n%s", strlen($string), $string);

    }

    /**
     * Converts message sequence-set into array
     *
     * @access public 
     * @param string $messages Message identifiers
     * @return array List of message identifiers
     */
    public static function uncompressMessageSet($messages)
    {
        if (empty($messages)) {
            return array();
        }

        $result   = array();
        $messages = explode(',', $messages);

        foreach ($messages as $idx => $part) {
            $items = explode(':', $part);
            $max   = max($items[0], $items[1]);

            for ($x=$items[0]; $x<=$max; $x++) {
                $result[] = (int)$x;
            }
            unset($messages[$idx]);
        }
        return $result;
    }

    /**
     * Converts message identifiers array into sequence-set syntax
     *
     * @access public 
     * @param array $messages Message identifiers
     * @param bool  $force    Forces compression of any size
     * @return string Compressed sequence-set
     */

    public static function compressMessageSet($messages, $force=false)
    {
        if (!is_array($messages)) {
            // if less than 255 bytes long, let's not bother
            if (!$force && strlen($messages)<255) {
                return $messages;
            }

            // see if it's already been compressed
            if (strpos($messages, ':') !== false) {
                return $messages;
            }
            $messages = explode(',', $messages);
        }
        sort($messages);

        $result = array();
        $start  = $prev = $messages[0];

        foreach ($messages as $id) {
            $incr = $id - $prev;
            if ($incr > 1) { // found a gap
                if ($start == $prev) {
                    $result[] = $prev; // push single id
                }else {
                    $result[] = $start . ':' . $prev; // push sequence as start_id:end_id
                }
                $start = $id; // start of new sequence
            }
            $prev = $id;
        }

        if ($start == $prev) {
            $result[] = $prev;
        }else {
            $result[] = $start.':'.$prev;
        }
        return implode(',', $result);
    }

    /**
     * Splits IMAP response into string tokens
     *
     * @access public
     * @param string &$str The IMAP's server response
     * @param int    $num  Number of tokens to return
     * @return mixed Tokens array or string if $num=1
     */

    public static function tokenizeResponse(&$str, $num=0)
    {
        $result = array();
        while (!$num || count($result) < $num) {
            $str = ltrim($str);
            switch ($str[0]) {
            case '{':
                if (($epos = strpos($str, "}\r\n", 1)) == false) {
                    // error
                }
                if (!is_numeric(($bytes = substr($str, 1, $epos - 1)))) {
                    // error
                }

                $result[] = $bytes ? substr($str, $epos + 3, $bytes) : '';
                $str      = substr($str, $epos + 3 + $bytes);
                break;
            case '"':
                $len = strlen($str);
                for ($pos=1; $pos<$len; $pos++) {
                    if ($str[$pos] == '"') {
                        break;
                    }
                    if ($str[$pos] == "\\") {
                        if ($str[$pos + 1] == '"' || $str[$pos + 1] == "\\") {
                            $pos++;
                        }
                    }
                }

                // we need to strip slashes for a quoted string
                $result[] = stripslashes(substr($str, 1, $pos - 1));
                $str      = substr($str, $pos + 1);
                break;
            case '(':
                $str      = substr($str, 1);
                $result[] = self::tokenizeResponse($str);
                break;

            case ')':
                $str = substr($str, 1);
                return $result;
            default:
                if ($str === '' || $str === null) {
                    break 2;
                }

                // excluded chars: SP, CTL, ), DEL
                // we do not exclude [ and ] (#1489223)
                if (preg_match('/^([^\x00-\x20\x29\x7F]+)/', $str, $m)) {
                    $result[] = $m[1] == 'NIL' ? null : $m[1];
                    $str      = substr($str, strlen($m[1]));
                }
                break;
            }
        }
        return $num == 1 ? $result[0] : $result;
    }

    /**
     * Joins IMAP command line elements (recursively)
     *
     * @access public 
     * @param  mixed  $element 
     * @return mixed 
     */

    public static function implodeRecursive($element)
    {
        $string = '';
        if (is_array($element)) {
            reset($element);
            foreach ($element as $value) {
                $string .= ' ' . self::implodeRecursive($value);
            }
        }
        else {
            return $element;
        }
        return '(' . trim($string) . ')';
    }


    /**
     * Similar function as in_array() but case-insensitive with multibyte support.
     *
     * @param string $needle   Needle value
     * @param array  $heystack Array to search in
     *
     * @return boolean True if found, False if not
     */
    public static function in_array_nocase($needle, $haystack)
    {
        // use much faster method for ascii
        if (self::is_ascii($needle)) {
            foreach ((array) $haystack as $value) {
                if (strcasecmp($value, $needle) === 0) {
                    return true;
                }
            }
        }
        else {
            $needle = mb_strtolower($needle);
            foreach ((array) $haystack as $value) {
                if ($needle === mb_strtolower($value)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if a string contains only ascii characters
     *
     * @param string $str           String to check
     * @param bool   $control_chars Includes control characters
     *
     * @return bool
     */
    public static function is_ascii($str, $control_chars = true)
    {
        $regexp = $control_chars ? '/[^\x00-\x7F]/' : '/[^\x20-\x7E]/';
        return preg_match($regexp, $str) ? false : true;
    }


    /**
     * Explode quoted string
     *
     * @param string Delimiter expression string for preg_match()
     * @param string Input string
     *
     * @return array String items
     */
    public static function explode_quoted_string($delimiter, $string)
    {
        $result = array();
        $strlen = strlen($string);

        for ($q=$p=$i=0; $i < $strlen; $i++) {
            if ($string[$i] == "\"" && $string[$i-1] != "\\") {
                $q = $q ? false : true;
            }
            else if (!$q && preg_match("/$delimiter/", $string[$i])) {
                $result[] = substr($string, $p, $i - $p);
                $p = $i + 1;
            }
        }

        $result[] = (string) substr($string, $p);

        return $result;
    }

    /**
     * Clean up date string for strtotime() input
     *
     * @param string $date Date string
     *
     * @return string Date string
     */
    public static function clean_datestr($date)
    {
        $date = trim($date);

        // check for MS Outlook vCard date format YYYYMMDD
        if (preg_match('/^([12][90]\d\d)([01]\d)([0123]\d)$/', $date, $m)) {
            return sprintf('%04d-%02d-%02d 00:00:00', intval($m[1]), intval($m[2]), intval($m[3]));
        }

        // Clean malformed data
        $date = preg_replace(
            array(
                '/GMT\s*([+-][0-9]+)/',                     // support non-standard "GMTXXXX" literal
                '/[^a-z0-9\x20\x09:+-\/]/i',                // remove any invalid characters
                '/\s*(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s*/i',   // remove weekday names
            ),
            array(
                '\\1',
                '',
                '',
            ), $date);

        $date = trim($date);

        // try to fix dd/mm vs. mm/dd discrepancy, we can't do more here
        if (preg_match('/^(\d{1,2})[.\/-](\d{1,2})[.\/-](\d{4})(\s.*)?$/', $date, $m)) {
            $mdy   = $m[2] > 12 && $m[1] <= 12;
            $day   = $mdy ? $m[2] : $m[1];
            $month = $mdy ? $m[1] : $m[2];
            $date  = sprintf('%04d-%02d-%02d%s', $m[3], $month, $day, $m[4] ?: ' 00:00:00');
        }
        // I've found that YYYY.MM.DD is recognized wrong, so here's a fix
        else if (preg_match('/^(\d{4})\.(\d{1,2})\.(\d{1,2})(\s.*)?$/', $date, $m)) {
            $date  = sprintf('%04d-%02d-%02d%s', $m[1], $m[2], $m[3], $m[4] ?: ' 00:00:00');
        }

        return $date;
    }

    /**
     * Improved equivalent to strtotime()
     *
     * @param string       $date     Date string
     * @param DateTimeZone $timezone Timezone to use for DateTime object
     *
     * @return int Unix timestamp
     */
    public static function strtotime($date, $timezone = null)
    {
        $date   = self::clean_datestr($date);
        $tzname = $timezone ? ' ' . $timezone->getName() : '';

        // unix timestamp
        if (is_numeric($date)) {
            return (int) $date;
        }

        // if date parsing fails, we have a date in non-rfc format.
        // remove token from the end and try again
        while ((($ts = @strtotime($date . $tzname)) === false) || ($ts < 0)) {
            $d = explode(' ', $date);
            array_pop($d);
            if (!$d) {
                break;
            }
            $date = implode(' ', $d);
        }

        return (int) $ts;
    }

 /**
     * Replacing specials characters to a specific encoding type
     *
     * @param string  Input string
     * @param string  Encoding type: text|html|xml|js|url
     * @param string  Replace mode for tags: show|remove|strict
     * @param boolean Convert newlines
     *
     * @return string The quoted string
     */
    public static function rep_specialchars_output($str, $enctype = '', $mode = '', $newlines = true)
    {
        static $html_encode_arr = false;
        static $js_rep_table    = false;
        static $xml_rep_table   = false;

        if (!is_string($str)) {
            $str = strval($str);
        }

        // encode for HTML output
        if ($enctype == 'html') {
            if (!$html_encode_arr) {
                $html_encode_arr = get_html_translation_table(HTML_SPECIALCHARS);
                unset($html_encode_arr['?']);
            }

            $encode_arr = $html_encode_arr;

            if ($mode == 'remove') {
                $str = strip_tags($str);
            }
            else if ($mode != 'strict') {
                // don't replace quotes and html tags
                $ltpos = strpos($str, '<');
                if ($ltpos !== false && strpos($str, '>', $ltpos) !== false) {
                    unset($encode_arr['"']);
                    unset($encode_arr['<']);
                    unset($encode_arr['>']);
                    unset($encode_arr['&']);
                }
            }

            $out = strtr($str, $encode_arr);

            return $newlines ? nl2br($out) : $out;
        }

        // if the replace tables for XML and JS are not yet defined
        if ($js_rep_table === false) {
            $js_rep_table = $xml_rep_table = array();
            $xml_rep_table['&'] = '&amp;';

            // can be increased to support more charsets
            for ($c=160; $c<256; $c++) {
                $xml_rep_table[chr($c)] = "&#$c;";
            }

            $xml_rep_table['"'] = '&quot;';
            $js_rep_table['"']  = '\\"';
            $js_rep_table["'"]  = "\\'";
            $js_rep_table["\\"] = "\\\\";
            // Unicode line and paragraph separators (#1486310)
            $js_rep_table[chr(hexdec('E2')).chr(hexdec('80')).chr(hexdec('A8'))] = '&#8232;';
            $js_rep_table[chr(hexdec('E2')).chr(hexdec('80')).chr(hexdec('A9'))] = '&#8233;';
        }

        // encode for javascript use
        if ($enctype == 'js') {
            return preg_replace(array("/\r?\n/", "/\r/", '/<\\//'), array('\n', '\n', '<\\/'), strtr($str, $js_rep_table));
        }

        // encode for plaintext
        if ($enctype == 'text') {
            return str_replace("\r\n", "\n", $mode == 'remove' ? strip_tags($str) : $str);
        }

        if ($enctype == 'url') {
            return rawurlencode($str);
        }

        // encode for XML
        if ($enctype == 'xml') {
            return strtr($str, $xml_rep_table);
        }

        // no encoding given -> return original string
        return $str;
    }

      /*
     * Idn_to_ascii wrapper.
     * Intl/Idn modules version of this function doesn't work with e-mail address
     */
    public static function idn_to_ascii($str)
    {
        return self::idn_convert($str, true);
    }

    /*
     * Idn_to_ascii wrapper.
     * Intl/Idn modules version of this function doesn't work with e-mail address
     */
    public static function idn_to_utf8($str)
    {
        return self::idn_convert($str, false);
    }

    public static function idn_convert($input, $is_utf = false)
    {
        if ($at = strpos($input, '@')) {
            $user   = substr($input, 0, $at);
            $domain = substr($input, $at+1);
        }
        else {
            $domain = $input;
        }

        $domain = $is_utf ? self::idn_to_ascii($domain) : self::idn_to_utf8($domain);

        if ($domain === false) {
            return '';
        }

        return $at ? $user . '@' . $domain : $domain;
    }

     /**
     * Generate a random string
     *
     * @param int  $length String length
     * @param bool $raw    Return RAW data instead of ascii
     *
     * @return string The generated random string
     */
    public static function random_bytes($length, $raw = false)
    {
        $hextab  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $tabsize = strlen($hextab);

        // Use PHP7 true random generator
        if ($raw && function_exists('random_bytes')) {
            return random_bytes($length);
        }

        if (!$raw && function_exists('random_int')) {
            $result = '';
            while ($length-- > 0) {
                $result .= $hextab[random_int(0, $tabsize - 1)];
            }

            return $result;
        }

        $random = openssl_random_pseudo_bytes($length);

        if ($random === false) {
            throw new Exception("Failed to get random bytes");
        }

        if (!$raw) {
            for ($x = 0; $x < $length; $x++) {
                $random[$x] = $hextab[ord($random[$x]) % $tabsize];
            }
        }

        return $random;
    }

    /**
     * Convert binary data into readable form (containing a-zA-Z0-9 characters)
     *
     * @param string $input Binary input
     *
     * @return string Readable output (Base62)
     * @deprecated since 1.3.1
     */
    public static function bin2ascii($input)
    {
        $hextab = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $result = '';

        for ($x = 0; $x < strlen($input); $x++) {
            $result .= $hextab[ord($input[$x]) % 62];
        }

        return $result;
    }

    /**
     * Format current date according to specified format.
     * This method supports microseconds (u).
     *
     * @param string $format Date format (default: 'd-M-Y H:i:s O')
     *
     * @return string Formatted date
     */
    public static function date_format($format = null)
    {
        if (empty($format)) {
            $format = 'd-M-Y H:i:s O';
        }

        if (strpos($format, 'u') !== false) {
            $dt  = number_format(microtime(true), 6, '.', '');
            $dt .=  '.' . date_default_timezone_get();

            if ($date = date_create_from_format('U.u.e', $dt)) {
                return $date->format($format);
            }
        }

        return date($format);
    }

    public static function show_bytes($bytes, $unit = null)
    {
        if ($bytes >= 1073741824) {
            $unit = 'GB';
            $gb   = $bytes/1073741824;
            $str  = sprintf($gb >= 10 ? "%d " : "%.1f ", $gb) . $unit;
        }
        else if ($bytes >= 1048576) {
            $unit = 'MB';
            $mb   = $bytes/1048576;
            $str  = sprintf($mb >= 10 ? "%d " : "%.1f ", $mb) . $unit;
        }
        else if ($bytes >= 1024) {
            $unit = 'KB';
            $str  = sprintf("%d ",  round($bytes/1024)) . $unit;
        }
        else {
            $unit = 'B';
            $str  = sprintf('%d ', $bytes) . $unit;
        }

        return $str;
    }  


/**
 * intl replacement functions
 */

    public static function cidn_to_utf8($domain)
    {
        static $idn, $loaded;

        if (!$loaded) {
            $idn    = new Net_IDNA2();
            $loaded = true;
        }

        if ($idn && $domain && preg_match('/(^|\.)xn--/i', $domain)) {
            try {
                $domain = $idn->decode($domain);
            }
            catch (Exception $e) {
            }
        }

        return $domain;
    }

    public static function cidn_to_ascii($domain)
    {
        static $idn, $loaded;

        if (!$loaded) {
            $idn    = new Net_IDNA2();
            $loaded = true;
        }

        if ($idn && $domain && preg_match('/[^\x20-\x7E]/', $domain)) {
            try {
                $domain = $idn->encode($domain);
            }
            catch (Exception $e) {
            }
        }

        return $domain;
    }
}
