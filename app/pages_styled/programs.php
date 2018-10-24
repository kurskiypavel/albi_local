<?php

// Connection with DB
require_once '../config.php';
require_once '../classes/programClass.php';

$user = $_GET['user'];

$classProgram = new programClass($conn);


//add dynamic favorite
if ($_POST) {

    foreach ($_POST as $name => $value) {
        //pass dynamic name from $_POST input

        if (strpos($name,'DISLIKE') !== false) {
            $name = str_replace('DISLIKE', '', $name);
            $classProgram->deleteFromFavorites($name);
        } else{
            $classProgram->addToFavorite($user,$name);
        }
    }

}

?>


<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
    <link href="https://cdn.jsdelivr.net/npm/flexiblegrid@v1.2.2/dist/css/flexible-grid.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../../assets/css/styleApp.css">
    <link rel="stylesheet" href="../../assets/css/reset.css">
    <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.3.1/css/all.css" integrity="sha384-mzrmE5qonljUremFsqc01SB46JvROS7bZs3IO2EmfFsd15uHvIt+Y8vEf7N7fWAU"
        crossorigin="anonymous">


    <!-- FONTS IMPORT -->
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
<?php
//select user data
$queryUser = "SELECT level FROM users WHERE level='Instructor' AND id='$user'";
$result = $conn->query($queryUser);
if (!$result) die($conn->connect_error);
$rows = $result->num_rows;
$objUser = $result->fetch_object();


?>
    <div class="header">
        <div class="searchBar">
            <div class="input">
                <input type="text" placeholder="Search programs...">
                <i class="fas fa-search"></i>
            </div>
        </div>
        <ul class='programLists'>
            <li >New Programs</li>
            <li class="active">All Programs</li>
        </ul>

    </div>

    <div style="display: none;" class="programs new">

        <?php

        $query = "SELECT * FROM programs WHERE new='1'";
        $result = $conn->query($query);
        if (!$result) die($conn->connect_error);
        $rows = $result->num_rows;

        for ($i = 0; $i < $rows; ++$i) {
            $result->data_seek($i);
            $obj = $result->fetch_object();

            echo '<a href="program.php?user=' . $user . '&id=' . $obj->id . '">
            <div class="program">
                <div class="headerProgram" style="background-image: url(../../assets/images/App/'.$obj->image.');">
                    <ul>
                        <li class="share"><img src="/assets/images/App/share-solid.svg" alt="share"></li>
                        <li class="like">
                            <img class="likeHeart" src="/assets/images/App/heart-solid.svg" alt="like">
                            <!-- <img  class="likeHeart liked" src="/assets/images/App/heart-not-solid.svg" alt="liked"> -->
                        </li>
                    </ul>
                </div>
                <div class="body">
                    <h3>'.$obj->title.'</h3>
                    <div class="features">
                        <ul>
                            <li><img src="../../assets/images/App/calendar-regular.svg" alt="calIcon">
                                <p>Every '.$obj->schedule.'</p>
                            </li>
                            <li>
                                <p>Level: <span class="bold">'. $obj->level .'</span></p>
                            </li>
                            <li>
                                <p>Duration: <span class="bold">' . $obj->duration . ' min</span></p>
                            </li>
                        </ul>
                    </div>

                    <div class="description">
                        <h3>Description</h3>
                        <p class="shortDescription">' . $obj->description . '</p>

                        <p class="more">read more</p>

                    </div></a>';



                    //        booking functionality
                    $queryEvent = "select id from events WHERE program='$obj->id' AND student='$user'";
                    $resultEvent = $conn->query($queryEvent);
                    $rowsEvent = $resultEvent->num_rows;
                    $objEvent = $resultEvent->fetch_object();
                    //book place - redirect to bookGroupevent
                    if (!$objEvent) {
                        echo '<button class="book" onclick="location.href =\'bookGroupEvent.php?user='.$user.'&page=programs&program=' . $obj->id . '&student=' . $user . '&instructor=' . $obj->instructor_id.'\'">Book place in group</button>';
                    } elseif ($objEvent) {
                        //already booked - event query
                        echo '<button class="booked" onclick="location.href =\'changeGroupEvent.php?user='.$user.'&page=programs&id='.$objEvent->id.'\'">Change booking</button>';
                    }

                echo '</div>
            </div>
        ';
        }

        ?>



    </div>

<div class="programs all">

    <?php

    $query = "SELECT * FROM programs";
    $result = $conn->query($query);
    if (!$result) die($conn->connect_error);
    $rows = $result->num_rows;

    for ($i = 0; $i < $rows; ++$i) {
        $result->data_seek($i);
        $obj = $result->fetch_object();

        echo '<a href="program.php?user=' . $user . '&id=' . $obj->id . '">
            <div class="program">
                <div class="headerProgram" style="background-image: url(../../assets/images/App/programs-images/'.$obj->image.');">
                    <ul>
                        <li class="share"><img src="/assets/images/App/share-solid.svg" alt="share"></li>
                        <li class="like">
                            <img class="likeHeart" src="/assets/images/App/heart-solid.svg" alt="like">
                            <!-- <img  class="likeHeart liked" src="/assets/images/App/heart-not-solid.svg" alt="liked"> -->
                        </li>
                    </ul>
                </div>
                <div class="body">
                    <h3>'.$obj->title.'</h3>
                    <div class="features">
                        <ul>
                            <li><img src="../../assets/images/App/calendar-regular.svg" alt="calIcon">
                                <p>Every '.$obj->schedule.'</p>
                            </li>
                            <li>
                                <p>Level: <span class="bold">'. $obj->level .'</span></p>
                            </li>
                            <li>
                                <p>Duration: <span class="bold">' . $obj->duration . ' min</span></p>
                            </li>
                        </ul>
                    </div>

                    <div class="description">
                        <h3>Description</h3>
                        <p class="shortDescription">' . $obj->description . '</p>

                        <p class="more">read more</p>

                    </div></a>';



        //        booking functionality
        $queryEvent = "select id from events WHERE program='$obj->id' AND student='$user'";
        $resultEvent = $conn->query($queryEvent);
        $rowsEvent = $resultEvent->num_rows;
        $objEvent = $resultEvent->fetch_object();
        //book place - redirect to bookGroupevent
        if (!$objEvent) {
            echo '<button class="book" onclick="location.href =\'bookGroupEvent.php?user='.$user.'&page=programs&program=' . $obj->id . '&student=' . $user . '&instructor=' . $obj->instructor_id.'\'">Book place in group</button>';
        } elseif ($objEvent) {
            //already booked - event query
            echo '<button class="booked" onclick="location.href =\'changeGroupEvent.php?user='.$user.'&page=programs&id='.$objEvent->id.'\'">Change booking</button>';
        }

        echo '</div>
            </div>
        ';
    }

    ?>



</div>



    <script src='//cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.min.js'></script>
<?php include_once '../parts/footer.php' ?>
</body>

</html>