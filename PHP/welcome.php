<?php

/** PBKDF2 Implementation (described in RFC 2898)
 *
 *  @param string p password
 *  @param string s salt
 *  @param int c iteration count (use 1000 or higher)
 *  @param int kl derived key length
 *  @param string a hash algorithm
 *
 *  @return string derived key
*/
function pbkdf2( $p, $s, $c, $kl, $a = 'sha256' ) {
 
    $hl = strlen(hash($a, null, true)); # Hash length
    $kb = ceil($kl / $hl);              # Key blocks to compute
    $dk = '';                           # Derived key
 
    # Create key
    for ( $block = 1; $block <= $kb; $block ++ ) {
 
        # Initial hash for this block
        $ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);
 
        # Perform block iterations
        for ( $i = 1; $i < $c; $i ++ )
 
            # XOR each iterate
            $ib ^= ($b = hash_hmac($a, $b, $p, true));
 
        $dk .= $ib; # Append iterated block
    }
 
    # Return derived key of correct length
    return substr($dk, 0, $kl);
}
$username = strip_tags(substr($_POST['username'],0,32));
$password = strip_tags(substr($_POST['password'],0,32));
$outhash = pbkdf2($username,$password,10000,16);
$testname = "Greg";
$testpass = "hahaha";
$testhash = pbkdf2($testname,$testpass,10000,16);

if($outhash == $testhash)
{
 header( 'Location: admin.php' ) ;

}
else
{
 header('Location: http://www.yahoo.com');
}
?>
<html>
<body>
</body>
</html>