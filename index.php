<?php
// Connection with DB
//  include_once 'config/config.php';


//INCLUDE THIS FILE ON SUCCESS RESPONSE FROM FB
//include_once 'config/query.php';

?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Albi</title>

    <link href="https://cdn.jsdelivr.net/npm/flexiblegrid@v1.2.2/dist/css/flexible-grid.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
    <link rel="stylesheet" href="assets/css/reset.css">


    <script>
        (function (d) {
            var config = {
                    kitId: 'wkb3jgo',
                    scriptTimeout: 3000,
                    async: true
                },
                h = d.documentElement,
                t = setTimeout(function () {
                    h.className = h.className.replace(/\bwf-loading\b/g, "") + " wf-inactive";
                }, config.scriptTimeout),
                tk = d.createElement("script"),
                f = false,
                s = d.getElementsByTagName("script")[0],
                a;
            h.className += " wf-loading";
            tk.src = 'https://use.typekit.net/' + config.kitId + '.js';
            tk.async = true;
            tk.onload = tk.onreadystatechange = function () {
                a = this.readyState;
                if (f || a && a != "complete" && a != "loaded") return;
                f = true;
                clearTimeout(t);
                try {
                    Typekit.load(config)
                } catch (e) {
                }
            };
            s.parentNode.insertBefore(tk, s)
        })(document);
    </script>


</head>

<body>

<div id="fb-root"></div>
<script>
    window.fbAsyncInit = function () {
        FB.init({
            appId: '326104261280924',
            cookie: true,
            xfbml: true,
            version: 'v3.1',
            autoLogAppEvents: true
        });

        FB.AppEvents.logPageView();


        FB.getLoginStatus(function (response) {

        });

        $('.fb').click(login);

        $('.fbOut').click(logOut);

        function login(response) {
            FB.login(function (response) {
                if (response.status === 'connected') {
                    console.log(response.authResponse.accessToken);
                    FB.api('/me?fields=email,name', function (response) {
                        console.log(JSON.stringify(response));
                        alert('Now we know who you are!' + JSON.stringify(response));
                    });
                } else {
                    console.log(response);
                    console.log('login');
                }
            });
        };

        function logOut(response) {
            FB.logout(function (response) {
                console.log(response);
            });
        };


    };

    (function (d, s, id) {
        var js, fjs = d.getElementsByTagName(s)[0];
        if (d.getElementById(id)) {
            return;
        }
        js = d.createElement(s);
        js.id = id;
        js.src = "https://connect.facebook.net/en_US/sdk.js";
        fjs.parentNode.insertBefore(js, fjs);
    }(document, 'script', 'facebook-jssdk'));
</script>

<div class="mainSlider">
    <div class="container">
        <div class="header row d-flex flex-d-row">
            <div class="column xl-12">
                <img class='logo' src="assets/images/logo.svg" alt="">
            </div>
        </div>
        <div class="section row d-flex flex-d-row">
            <div class="column xl-6 block">
                <h1>Discover your body</h1>
                <div class="p">
                    <p>Hire an expert and extend the limits of</p>
                    <p>your body and mind.</p>
                </div>

                <div class="buttons">
                    <!-- <button class="fb">Continue with Facebook</button> -->

                    <button class="phone">Sign in with your phone</button>
                </div>
            </div>
            <div class="column xl-6">

            </div>


        </div>
    </div>
    <img src="assets/images/footer1.png" alt="" class="footer1">
</div>

<div class="container">

    <div class="sectionTwo">
        <div class="content row d-flex flex-d-row">
            <div class="row d-flex flex-d-row">
                <div class="column xl-4">
                    <h1>Exclusive Programs</h1>
                </div>
                <div class="column xl-8">
                    <p>Hire an expert and extend the limits of your body and mind. Hire an expert and extend the
                        limits
                        of your body and mind.</p>
                </div>
            </div>
        </div>

        <img src="assets/images/iphoneX-perspective.png" alt="" class="phoneOne">

        <button class="fbTwo">Continue with Facebook</button>
    </div>


</div>

<div class="containerThree">
    <div class="sectionThree">
        <div class="content row d-flex flex-d-row">
            <div class="row d-flex flex-d-row">
                <div class="column xl-4">
                    <h1>Exclusive Programs</h1>
                </div>
                <div class="column xl-8">
                    <p>Hire an expert and extend the limits of your body and mind. Hire an expert and extend the
                        limits
                        of your body and mind.</p>
                </div>
            </div>
        </div>

        <img src="assets/images/iphone-8-mockup-downloadable.png" alt="" class="phoneTwo">


    </div>
</div>

<div class="containerFour">
    <div class="sectionFour">
        <div class="buttons">
            <button class="fbThree">Continue with Facebook</button>
            <button class="phone phoneBtn">Sign in with your phone</button>
        </div>
    </div>
</div>

<!-- <button class="fbOut">Log out FB</button> -->

<div class="thankYou">
    <div class="content">
        <h1>Thank you!</h1>
        <p>We do our best to bring this app to life.</p>
        <p>Though, you can see our progress on Instagram.</p>
        <a href="https://www.instagram.com/yoga_albi/"><img src="/assets/images/IG_Glyph_Fill.svg" alt=""></a> 
    </div>
</div>


<div class="mobile">
    <div class="content">
        <form id="form" action="" method="post">
            <div class="phone">
                <img class="arrow left" src="assets/images/arrow-left-solid.svg" alt="">
                <h1>Sign in with phone</h1>
                <h2>Enter your mobile phone</h2>
                <div class="inputs">
                    <!-- <img class="left CC" src="assets/images/44.png" alt=""> -->
                    <input name="CC" class='left CC' type="tel" placeholder="1">
                    <!-- <img src="assets/images/289.png" alt=""> -->
                    <input name="pNumber" id='yourphone2' class='tel' type="tel" placeholder="e.g. (289) 830-1724">

                </div>
                <p>To secure your profile we will send you cute </p>
                <p>smart code on the number you provided here.</p>
                <p>Please use it to verify your number.</p>
                <button class="signIn">Sign in</button>

            </div>
        </form>
    </div>
</div>


<script src='//cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.min.js'></script>
<script src='//s3-us-west-2.amazonaws.com/s.cdpn.io/3/jquery.inputmask.bundle.js'></script>
<script src="assets/js/phoneMask.js"></script>
<script src="assets/js/main.js"></script>

<script>

    $(document).ready(function () {

        $('button.signIn').on("click", function () {

            var CC = $('.CC').val();

            var pNumber = $('#yourphone2').val();

            checkUser(CC, pNumber);
        });


        function checkUser(CC, pNumber) {

            $.ajax({
                type: 'POST',
                url: 'config/save_phone.php',
                data: {CC: CC, pNumber: pNumber}

            });

        }
    })
</script>

</body>

</html>