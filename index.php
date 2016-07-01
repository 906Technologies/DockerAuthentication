<?php
use Firebase\JWT\JWT;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ParameterBag;
use Silex\Application;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;
				
require_once __DIR__.'/vendor/autoload.php';

try {
	$config = Yaml::parse(file_get_contents('config.yml'));
} catch (ParseException $e) {
    die('Unable to parse config.yml');
}
$app = new Application();

$privateKey = openssl_pkey_get_private(file_get_contents($config['private_key']));

$log = new Logger('name');
$log->pushHandler(new StreamHandler('auth.log', Logger::INFO));

class TokenGenerator {
	private $user;
	private $issuer;
	private $audience;
	private $privateKey;
	private $kid;
	
	
	public function __construct($issuer, $audience, $privateKey) {
		$this->issuer = $issuer;
		$this->audience = $audience;
		$this->privateKey = $privateKey;
		$this->kid = $this->getKid($this->privateKey);
	}
	
	public function setUser($user){
		$this->user = $user;
	}
	
	public function createAccessToken($scope, $expires){
		$token = array(
			"iss" => $this->issuer,
			"aud" => $this->audience,
			"iat" => time(), // (Issued At)
			"nbf" => time(), // (Not Before)
			"sub" => $this->user,
			"jti" => uniqid() // (JWT ID)
		);
		$token["exp"] = $expires;

		$token['access'] = [];

		$token['access'][] = [
			'type' => 'registry',
			'name' => 'catalog',
			'actions' => ['*']
		];

		if($scope){
			list($type, $name, $actions) = explode(":", $scope, 3);
			$actions = explode(",", $actions);

			$token['access'][] = [
				'type' => $type,
				'name' => $name,
				'actions' => $actions
			];
		}
		return JWT::encode($token, $this->privateKey, 'RS256', $this->kid);
	}
	
	public function createRefreshToken(){
		$token = array(
			"iss" => $this->issuer,
			"aud" => $this->audience,
			"iat" => time(), // (Issued At)
			"nbf" => time(), // (Not Before)
			"sub" => $this->user,
			"jti" => uniqid() // (JWT ID)
		);
		return JWT::encode($token, $this->privateKey, 'RS256', $this->kid);
	}
	
	private function getKid($privateKey){
		$details = openssl_pkey_get_details($privateKey);

		$publicKey = str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----'], '', $details['key']);
		$publicKey = trim($publicKey);
		$der = base64_decode($publicKey);

		$hashDer = hash('sha256', $der, true);

		$first30bytes = substr($hashDer, 0, 30);

		$libtrust = Base32\Base32::encode($first30bytes);

		$chunks = [];

		for ($i = 0, $max = 48; $i < $max; $i += 4) {
			$chunk = substr($libtrust, $i, 4);
			$chunks[] = $chunk;
		}

		$fingerprint = implode(":", $chunks);

		return $fingerprint;
	}
	
	function verifyRefreshToken($token){
		try{
			$details = openssl_pkey_get_details($this->privateKey);
			$publicKey = openssl_pkey_get_public($details['key']);
			$payload = JWT::decode($token, $publicKey, array('RS256'));
		} catch (\Firebase\JWT\ExpiredException $e){
			return false;
		} catch (\Exception $e){
			return false;
		}
		return $payload;
	}
}

//$app['debug'] = true;

function pamAuthenticate($user, $password, $blacklistedUsers = array()){
	if (!$user || !$password || strlen($user) > 30 || strlen($password) > 60){
		throw new \Exception ('Missing Creds');
	}

	$error = '';

	if (in_array($user, $blacklistedUsers) || !pam_auth($user, $password, $error, false)) {
		throw new \Exception ('Pam Authenticaiton Failed : '.$error);
	}
	return true;
}
 
$app->get('/', function (Request $request) {
	return  "<h1>This is not the auth you are looking for</h1>";
});


$app->get('/docker/v2/token', function (Request $request) use ($app, $privateKey, $log, $config) {
	JWT::$leeway = 60; // $leeway in seconds
	$log->info('Requested', [$request->getUri()]);
	
	//$log->info('Headers', $request->headers->all());
	
	$authorizationHeader = $request->headers->get('authorization');
	
	if(!$authorizationHeader){
		$log->error('Missing authorization Header', []);
		return $app->json(
			["errors" => [
				"code" => "UNAUTHORIZED"
				]
			], 401);
	}
	
	if (strpos($authorizationHeader, "Basic") !== 0){
		$log->error('Missing Basic auth Header', []);
		return $app->json(
			["errors" => [
				"code" => "UNAUTHORIZED"
				]
			], 401);
	}
	

	$log->info('Params', $request->query->all());

	$credentialsEncoded = str_replace('Basic ', '', $authorizationHeader);
	list($user, $password) = explode(':', base64_decode($credentialsEncoded), 2);

	$log->info('User', ["username"=>$user]);

	try{
		if(!isset($config["blacklisted_users"])){
			$config["blacklisted_users"] = array();
		}
		
		pamAuthenticate($user, $password, $config["blacklisted_users"]);

		$tokenGenerator = new TokenGenerator($config["issuer"], $config["audience"], $privateKey);
		$tokenGenerator->setUser($user);


		if($request->query->get("offline_token") == true){
			$log->info('Offline Token Requested',[]);
			$now = new \DateTime();
			$expires = strtotime('+3 day', time());
			
			return $app->json([
				'access_token' => $tokenGenerator->createAccessToken($request->query->get('scope'), $expires),
				'refresh_token' => $tokenGenerator->createRefreshToken(),
				'expires_in' => ($expires - time()),
				'issued_at' => $now->format(\DateTime::RFC3339)
			], 200, array());
		} 

		$log->error('offline token request missing, docker version of requester might be out of date', []);
		return $app->json(
			["errors" => [
				"code" => "UNAUTHORIZED"
				]
			], 401);


	} catch (\Exception $e){
		$log->error('Validation Error: '.$e->getMessage(), []);
		return $app->json('Invalid Credentials', 403);
	}

});

$app->post('/docker/v2/token', function (Request $request) use ($app, $privateKey, $log, $config) {
	$log->info('TOKEN VERIFICATION REQUESTED', [$request->getUri()]);
	
	$log->info('REQUEST', $request->request->all());
	
	$tokenGenerator = new TokenGenerator($config["issuer"], $config["audience"], $privateKey);
	
	$refreshToken = $request->request->get('refresh_token');
	$refreshTokenPayload = $tokenGenerator->verifyRefreshToken($refreshToken);
	
	$log->info('TOKEN PAYLOAD', [$refreshTokenPayload]);
	
	if(!$refreshTokenPayload){
		$log->error('Token Expired', []);
		return $app->json('Invalid Token', 403);
	}
	
	$user = $refreshTokenPayload->sub;
	
	$log->info('USER', [$user]);
	
	$scope = $request->request->get('scope');
	
	$log->info('SCOPE', [$scope]);
	
	$tokenGenerator->setUser($user);
	
	
	$now = new \DateTime();
	$expires = strtotime('+3 day', time());
	
	$response = [
		'access_token' => $tokenGenerator->createAccessToken($request->request->get('scope'), $expires),
		'refresh_token' => $refreshToken,
		'expires_in' => ($expires - time()),
		'issued_at' => $now->format(\DateTime::RFC3339)
	];
	
	$log->info('RESPONSE', $response);

	return $app->json($response, 200);	
});


$app->run();


/*
//attempt at geting docker registry to accept x5c claim in the header, correct formating done here but still untrusted by registry 
$fullChainContents = file_get_contents("/path/to/fullchain.pem");
$x5c = explodeChain($fullChainContents);
function explodeChain($chainContents){
	$chainLines = explode("\n", $chainContents);
	//print_r($chainLines);
	$x5c = [];
	$lines = [];
	foreach($chainLines as $chainLine){
		if(strlen($chainLine) == 0 || strpos($chainLine, "-----BEGIN") === 0){
			continue;
		}

		if(strpos($chainLine, "-----END") === 0){
			$chainLink = implode("", $lines);
			$x5c[] = $chainLink;//base64_encode($chainLink);
			$lines = [];
		} else {
			$lines[] = $chainLine;
		}
	}
	return $x5c;
}*/