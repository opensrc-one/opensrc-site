<?php
if (!isset($_POST['view-address']) || !isset($_POST['coin'])) { header("Location: https://opensrc.one/"); exit; }

$coin_ticker = $_POST['coin'];
$coin_list = array (
    'xmr' => array('name' => 'Monero', 'address' => '84W8YaFgeEXKoQz28QKZCq7T5UJGvjpQ4FEuTRdZrzknca9cXGhtf27gyvDTfQ9bvhUfQ22Pda5gDjUf9dE6CZEPTNKYAdq'),
    'wow' => array('name' => 'Wownero', 'address' => 'WW3C6aNUEsY5YxnHYiZHh7dAihgURt72zd64tFLVnYfxDTyGpomQjji13xdNynLzC1cd5JauvXhCMKUVTHxQekyQ1PdCJF8Rs'),
    'zec' => array('name' => 'ZCash', 'address' => 'zs128cux9cuc8cj0739a4m0usp706vtukxsvvagmk0qtuetr9w45x66hr0ftms4cnyg46s765r3fev'),
    'ltc' => array('name' => 'Litecoin', 'address' => 'ltc1q6h8rdjan4hjh8yfnrdyu6cmpzt9klyqkyy58qv'),
    'btc' => array('name' => 'Bitcoin', 'address' => 'bc1q6zwj347tu804qg3486ee86r7cwdt4z82hq4tlp')
);
?>

<!DOCTYPE html>
<html>
    <head>
        <title>opensrc.one - Donate</title>

        <meta charset="UTF-8">
        <meta name="description" content="Open source software and services.">
        <meta name="keywords" content="opensrc, monero, anonymous, security, xmr, monero node, xmr node">
        <meta name="author" content="opensrc">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <meta http-equiv="Onion-Location" content="http://opensrc5aqxbfanpzgyrn2tjq7juvpuvqm5rrw2ztxcxooajpsjyfrid.onion">
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
                    <img src="../static/img/logo.png" alt="opensrc.one">
                </div>
                <div class="nav">
                    <ul>
                        <li><a href="../..">Home</a></li>
                        <li><a href="../xmrnode">XMR Node</a></li>
                        <li><a href="../contact">Contact</a></li>
                    </ul>
                </div>
            </div>
        </div>
        <div class="content">
            <div class="page">
                <div class="home">
                    <div class="page-header">
                        <h2><?php echo($coin_list[$selected_coin]['name'] . ' (' . strtoupper($coin_ticker) . ')'); ?> Donation Address</h2>
                    </div>
                    <div class="page-content">
                        <p>
                            Any funds sent to this wallet will be used to help develop opensrc.one software and services.
                        </p>
                    </div>
                </div>
                <hr>
                <div class="center-container">
                    <div class="crypto-address">
                        <textarea name="" id="" cols="80" rows="8" disabled><?php echo($coin_list[$coin_ticker]['address']); ?></textarea>
                    </div>
                    <div class="qr-code">
                        <img src="../static/img/crypto-qr/<?php echo($coin_ticker . '-qr.png'); ?>" alt="QR Code">
                    </div>
                </div>
            </div>
        </div>
        <div class="footer">
            <ul>
                <li><a href="../privacy-policy" target="_blank">Privacy Policy</a></li>
                <li><a href="https://github.com/Ashintosh/opensrc.one" target="_blank">Source</a></li>
                <li><a href="../pgp.txt" target="_blank">PGP</a></li>
                <li><a href="http://opensrc5aqxbfanpzgyrn2tjq7juvpuvqm5rrw2ztxcxooajpsjyfrid.onion">Onion</a></li>
                <li><a href="../canary.txt" target="_blank">Canary</a></li>
            </ul>
        </div>
    </body>
</html>