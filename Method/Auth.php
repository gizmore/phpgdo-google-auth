<?php
declare(strict_types=1);
namespace GDO\GoogleAuth\Method;

use GDO\Core\GDT;
use GDO\Core\Method;
use GDO\GoogleAuth\Module_GoogleAuth;
use GDO\Session\GDO_Session;
use GDO\UI\GDT_Redirect;

final class Auth extends Method
{
	public function isUserRequired(): bool { return false; }
	public function getUserType(): ?string { return 'ghost,guest'; }

	public function execute(): GDT
	{
		$google = Module_GoogleAuth::instance();
		if (!$google->isConfigured())
		{
			return $this->error('err_google_disabled');
		}
		$state = bin2hex(random_bytes(32));
		$nonce = bin2hex(random_bytes(32));
		$verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
		$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
		GDO_Session::set('google_auth', ['state' => $state, 'nonce' => $nonce, 'verifier' => $verifier, 'expires' => time() + 600]);
		GDO_Session::commit();
		return GDT_Redirect::to($google->authorizationURL($state, $nonce, $challenge));
	}
}
