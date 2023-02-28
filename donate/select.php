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
        $ticker = strtoupper($currency["ticker"]);
        $qr = $currency["ticker"] . "-qr.png";
        $url_data = "?ticker=" . $ticker . "&name=" . $currency['name'] . "&address=" . $currency['address'] . "&qr=" . $qr;

        header("Location: ../donate/" . $url_data);
        exit;
    }
}

header("Location: https://opensrc.one/");
exit;