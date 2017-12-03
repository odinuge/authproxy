package pkg

var LoginForm = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Whale Platform</title>
  <meta name="description" content="Default backend for the Whale Platform">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bulma/0.0.28/css/bulma.min.css">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.5.0/css/font-awesome.min.css">
  <link href='https://fonts.googleapis.com/css?family=Lobster' rel='stylesheet' type='text/css'>
  <style>
	.hero-whale {
  	  background-color: #555299;
	}
	.container {
      max-width: 300px;
	}
	.title-whale {
      color: #FFF;
      font-family: 'Lobster', cursive;
      font-size: 3em;
	}
	.title-status {
      color: #FFF;
      font-family: 'Lobster', cursive;
      font-size: 2em;
	}
	.field {
      margin-bottom: 20px;
	}
	.is-block {
      display: block!important;
	  width: 100%;
    }
	.social-icons {
      margin-top: 40px;
	}
	.social-icons a {
      font-size: 1.5em;
      color: #FFF;
      margin-right: 10px;
	}
	.social-icons a:last-child {
      margin-right: 0px;
	}
	.social-icons a:hover {
      color: #DDD;
	}
  </style>
</head>
<body>
  <section class="hero is-fullheight hero-whale">
    <div class="hero-body">
      <div class="container has-text-centered">
        <h1 class="title title-whale">
          Whale Platform
        </h1>
		<div class="box">
		  <form method="post">
			<div class="field">
			  <div class="control">
				<input class="input is-large" type="password" name="token" placeholder="JWT Token" autocomplete="off" style="background-image: url(&quot;data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAASCAYAAABSO15qAAAAAXNSR0IArs4c6QAAAPhJREFUOBHlU70KgzAQPlMhEvoQTg6OPoOjT+JWOnRqkUKHgqWP4OQbOPokTk6OTkVULNSLVc62oJmbIdzd95NcuGjX2/3YVI/Ts+t0WLE2ut5xsQ0O+90F6UxFjAI8qNcEGONia08e6MNONYwCS7EQAizLmtGUDEzTBNd1fxsYhjEBnHPQNG3KKTYV34F8ec/zwHEciOMYyrIE3/ehKAqIoggo9inGXKmFXwbyBkmSQJqmUNe15IRhCG3byphitm1/eUzDM4qR0TTNjEixGdAnSi3keS5vSk2UDKqqgizLqB4YzvassiKhGtZ/jDMtLOnHz7TE+yf8BaDZXA509yeBAAAAAElFTkSuQmCC&quot;); background-repeat: no-repeat; background-attachment: scroll; background-size: 16px 18px; background-position: 98% 50%; cursor: auto;">
              </div>
            </div>
		    <button type="submit" class="button is-block is-info is-large">Login</button>
		  </form>
		</div>

		<div class="social-icons">
		  <a href="http://github.com/getwhale"><i class="fa fa-github"></i></a>
		  <a href="mailto:contact@whale.io"><i class="fa fa-envelope-o"></i></a>
	  	</div>
      </div>
    </div>
  </section>
</body>
</html>
`
