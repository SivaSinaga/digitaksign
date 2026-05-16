<?php

$message = $_POST['message'];

$privateKey = openssl_pkey_get_private(
    file_get_contents("private.pem")
);

openssl_sign(
    $message,
    $signature,
    $privateKey,
    OPENSSL_ALGO_SHA256
);

$signatureBase64 = base64_encode($signature);

echo "<h3>Pesan:</h3>";
echo nl2br($message);

echo "<h3>SHA256:</h3>";
echo hash('sha256', $message);

echo "<h3>Signature:</h3>";
echo $signatureBase64;

?>