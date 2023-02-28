<?php
if (!isset($_POST['view-address']) || !isset($_POST['currency'])) { header("Location: https://opensrc.one/"); exit; }

$currency_ticker = null;
$currency_name = null;
$currency_address = null;
$currency_qr_code = null;

$currencies = array(
    array("ticker" => "xmr", "name" => "Monero", "address" => "84W8YaFgeEXKoQz28QKZCq7T5UJGvjpQ4FEuTRdZrzknca9cXGhtf27gyvDTfQ9bvhUfQ22Pda5gDjUf9dE6CZEPTNKYAdq"),
    array("ticker" => "wow", "name" => "Wownero", "address" => "WW3C6aNUEsY5YxnHYiZHh7dAihgURt72zd64tFLVnYfxDTyGpomQjji13xdNynLzC1cd5JauvXhCMKUVTHxQekyQ1PdCJF8Rs"),
    array("ticker" => "zec", "name" => "ZCash", "address" => "zs128cux9cuc8cj0739a4m0usp706vtukxsvvagmk0qtuetr9w45x66hr0ftms4cnyg46s765r3fev"),
    array("ticker" => "ltc", "name" => "Litecoin", "address" => "ltc1q6h8rdjan4hjh8yfnrdyu6cmpzt9klyqkyy58qv"),
    array("ticker" => "btc", "name" => "Bitcoin", "address" => "bc1q6zwj347tu804qg3486ee86r7cwdt4z82hq4tlp"),
);

foreach ($currencies as $currency) {
    if ($_POST["currency"] == $currency["ticker"]) {
        $currency_ticker = strtoupper($currency["ticker"]);
        $currency_name = $currency["name"];
        $currency_address = $currency["address"];
        $currency_qr_code = $currency["ticker"] . "-qr.png";
    }
}
?>

<!DOCTYPE html>
<html>
    <head>
        <title>opensrc.one - Donate</title>

        <meta charset="UTF-8">
        <meta name="description" content="Open source software and services.">
        <meta name="keywords" content="opensrc, Monero, Anonymous, Security, XMR, Monero Node, XMR Node">
        <meta name="author" content="opensrc">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="icon" type="image/x-icon" href="../static/img/favicon.ico">
    
        <!-- Styles -->
        <link rel="stylesheet" type="text/css" href="../static/css/styles.css">

        <!-- Fonts -->
        <link rel="stylesheet" type="text/css" href="../static/css/fonts.css">
    </head>
    <body>
        <div class="center-container">
            <div class="header">
                <div class="logo">
                    <img src="../static/img/logo.png" alt="opensrc">
                </div>
                <div class="nav">
                    <ul>
                        <li><a href="../">Home</a></li>
                        <li><a href="../xmrnode/">XMR Node</a></li>
                        <li><a href="../contact/">Contact</a></li>
                    </ul>
                </div>
            </div>
        </div>
        <div class="content">
            <div class="page">
                <div class="home">
                    <div class="page-header">
                        <h2><?php echo($currency_name ." (". $currency_ticker .")"); ?> Donation Address</h2>
                    </div>
                    <div class="page-content">
                        <p>
                            Any funds sent to this wallet will be used to help develop opensrc and
                            provide more services.
                        </p>
                    </div>
                </div>
                <hr>
                <div class="center-container">
                    <div class="crypto-address">
                        <textarea name="" id="" cols="80" rows="8" disabled><?php echo($currency_address); ?></textarea>
                    </div>
                    <div class="qr-code">
                        <img src="../static/img/crypto-qr/<?php echo($currency_qr_code); ?>" alt="QR Code">
                    </div>
                </div>
            </div>
        </div>
        <div class="footer">
            <ul>
                <li><a href="../legal/privacy-policy/" target="_blank">Privacy Policy</a></li>
                <li><a href="https://github.com/Ashintosh/opensrc.one" target="_blank">Source</a></li>
                <li><a href="../pgp.txt" target="_blank">PGP</a></li>
            </ul>
        </div>
    </body>
</html>