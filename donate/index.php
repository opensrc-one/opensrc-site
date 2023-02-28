<?php
if (!isset($_GET['ticker']) || !isset($_GET['name']) || !isset($_GET['address']) || !isset($_GET['qr'])) { header("Location: https://opensrc.one/"); exit; }
$selected_currency = array('ticker' => $_GET['ticker'], 'name' => $_GET['name'], 'address' => $_GET['address'], 'qr' => $_GET['qr']);
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
                        <h2><?php echo($selected_currency['name'] ." (". $selected_currency['ticker'] .")"); ?> Donation Address</h2>
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
                        <textarea name="" id="" cols="80" rows="8" disabled><?php echo($selected_currency['address']); ?></textarea>
                    </div>
                    <div class="qr-code">
                        <img src="../static/img/crypto-qr/<?php echo($selected_currency['qr']); ?>" alt="QR Code">
                    </div>
                </div>
            </div>
        </div>
        <div class="footer">
            <ul>
                <li><a href="../legal/privacy-policy/" target="_blank">Privacy Policy</a></li>
                <li><a href="https://github.com/Ashintosh/opensrc.one" target="_blank">Source</a></li>
                <li><a href="../pgp.txt" target="_blank">PGP</a></li>
                <li><a href="http://opensrc5aqxbfanpzgyrn2tjq7juvpuvqm5rrw2ztxcxooajpsjyfrid.onion">Onion</a></li>
            </ul>
        </div>
    </body>
</html>