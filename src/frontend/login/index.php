<!DOCTYPE html>
<html>
<head>
    <title>opensrc.one - Login</title>

    <meta charset="UTF-8">
    <meta name="description" content="Open source software and services.">
    <meta name="keywords" content="opensrc, monero, anonymous, security, xmr, monero node, xmr node">
    <meta name="author" content="opensrc">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <meta http-equiv="Onion-Location" content="http://opensrc5aqxbfanpzgyrn2tjq7juvpuvqm5rrw2ztxcxooajpsjyfrid.onion/guides">
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
                <li><a href="../">Home</a></li>
                <li><a href="../xmrnode">XMR Node</a></li>
                <li><a href="../guides">Guides</a></li>
                <li><a href="../contact">Contact</a></li>
            </ul>
        </div>
    </div>
</div>
<div class="content">
    <div class="page">
        <div class="page-header">
            <h2>Login</h2>
        </div>
        <div class="page-content">
            <p>
                Admin login for opensrc.one.
            </p>
        </div>
        <hr>
        <div class="page-content">
            <form action="login.php" method="post">
                <label>Username</label>
                <input type="text" name="username" required>

                <label>Password</label>
                <input type="password" name="password" required>

                <input type="submit" name="request-login" value="Login">
            </form>
        </div>

    </div>
</div>
<div class="footer">
    <ul>
        <li><a href="../privacy-policy" target="_blank">Privacy Policy</a></li>
        <li><a href="https://github.com/Ashintosh/opensrc.one" target="_blank">Source</a></li>
        <li><a href="../pgp.txt" target="_blank">PGP</a></li>
        <li><a href="http://opensrc5aqxbfanpzgyrn2tjq7juvpuvqm5rrw2ztxcxooajpsjyfrid.onion/xmrnode">Onion</a></li>
        <li><a href="../canary.txt" target="_blank">Canary</a></li>
    </ul>
</div>
</body>
</html>
