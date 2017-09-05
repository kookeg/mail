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


}
