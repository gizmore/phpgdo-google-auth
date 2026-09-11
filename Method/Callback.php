<?php
declare(strict_types=1);
namespace GDO\GoogleAuth\Method;

use GDO\Core\GDO_Exception;
use GDO\Core\GDT;
use GDO\Core\Method;
use GDO\GoogleAuth\Module_GoogleAuth;
use GDO\Login\Method\Form;
use GDO\Session\GDO_Session;

final class Callback extends Method
{
	public function isUserRequired(): bool { return false; }
	public function getUserType(): ?string { return 'ghost,guest'; }

	public function execute(): GDT
	{
		if (isset($_GET['error']))
		{
			return $this->error('err_google_cancelled');
		}
		$pending = GDO_Session::get('google_auth');
		GDO_Session::remove('google_auth');
		GDO_Session::commit();
		if (!is_array($pending) || ($pending['expires'] ?? 0) < time() || !isset($_GET['state'], $_GET['code']) || !hash_equals((string)$pending['state'], (string)$_GET['state']))
		{
			return $this->error('err_google_state');
		}
		try
		{
			$google = Module_GoogleAuth::instance();
			$user = $google->resolveProfile($google->profileFromCode((string)$_GET['code'], (string)$pending['verifier']));
			return Form::make()->loginSuccess($user);
		}
		catch (GDO_Exception $ex)
		{
			return $this->error($ex->getMessage());
		}
	}
}
