<?php
declare(strict_types=1);
namespace GDO\GoogleAuth;

use GDO\Avatar\GDO_UserAvatar;
use GDO\Core\GDO_Exception;
use GDO\Core\GDO_Module;
use GDO\Core\GDT_Checkbox;
use GDO\Core\GDT_Secret;
use GDO\Core\GDT_String;
use GDO\Core\GDT_Hook;
use GDO\Form\GDT_Form;
use GDO\Mail\Module_Mail;
use GDO\Net\GDT_IP;
use GDO\Net\GDT_Url;
use GDO\UI\GDT_Button;
use GDO\User\GDO_User;
use GDO\User\GDT_UserType;
use GDO\Util\FileUtil;

/** Google OpenID Connect authentication provider. */
final class Module_GoogleAuth extends GDO_Module
{
	private const AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
	private const TOKEN_URL = 'https://oauth2.googleapis.com/token';
	private const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';

	public int $priority = 46;

	public function getDependencies(): array { return ['Login', 'Register', 'Session', 'Mail', 'Net']; }

	public function getFriendencies(): array { return ['Avatar']; }

	public function getClasses(): array { return [GDO_GoogleAuthIdentity::class]; }

	public function onLoadLanguage(): void { $this->loadLanguage('lang/google_auth'); }

	public function getConfig(): array
	{
		$clientID = $clientSecret = null;
        if (FileUtil::isFile($this->filePath('secret.php')))
        {
            $json = require $this->filePath('secret.php');
			$clientID = $json->web->client_id ?? null;
            $clientSecret = $json->web->client_secret ?? null;
        }
		return [
			GDT_Checkbox::make('google_auth')->initial($clientID && $clientSecret ? '1' : '0'),
			GDT_Secret::make('google_client_id')->ascii()->caseS()->max(191)->initial($clientID),
			GDT_Secret::make('google_client_secret')->ascii()->caseS()->max(191)->initial($clientSecret),
			GDT_Checkbox::make('google_import_avatar')->initial('1'),
		];
	}

	public function getUserSettings(): array
	{
		return [GDT_String::make('google_real_name')->utf8()->max(191)->noacl()->hidden()];
	}

	public function cfgAuth(): bool { return $this->getConfigValue('google_auth'); }
	public function cfgClientID(): ?string { return $this->getConfigVar('google_client_id'); }
	public function cfgClientSecret(): ?string { return $this->getConfigVar('google_client_secret'); }
//	public function cfgRedirectURI(): ?string { return $this->getConfigVar('google_redirect_uri'); }
	public function cfgImportAvatar(): bool { return $this->getConfigValue('google_import_avatar'); }

	public function isConfigured(): bool
	{
		return $this->cfgAuth() && (bool)$this->cfgClientID() &&
			(bool)$this->cfgClientSecret() && (bool)$this->getRedirectURI();
	}

    private function getRedirectURI(): string
    {
        return GDT_Url::absolute('/googleauth.callback.html');
    }

	public function hookLoginForm(GDT_Form $form): void { $this->addButton($form); }
	public function hookRegisterForm(GDT_Form $form): void { $this->addButton($form); }

	private function addButton(GDT_Form $form): void
	{
		if ($this->isConfigured())
		{
			$form->actions()->addField(GDT_Button::make('link_google_auth')->secondary()->href(href('GoogleAuth', 'Auth')));
		}
	}

	public function authorizationURL(string $state, string $nonce, string $challenge): string
	{
		return self::AUTHORIZE_URL . '?' . http_build_query([
			'client_id' => $this->cfgClientID(),
			'redirect_uri' => $this->getRedirectURI(),
			'response_type' => 'code',
			'scope' => 'openid email profile',
			'state' => $state,
			'nonce' => $nonce,
			'code_challenge' => $challenge,
			'code_challenge_method' => 'S256',
			'prompt' => 'select_account',
		], '', '&', PHP_QUERY_RFC3986);
	}

	/** @throws GDO_Exception */
	public function profileFromCode(string $code, string $verifier): array
	{
		$token = $this->requestJSON(self::TOKEN_URL, [
			'code' => $code,
			'client_id' => $this->cfgClientID(),
			'client_secret' => $this->cfgClientSecret(),
			'redirect_uri' => $this->getRedirectURI(),
			'grant_type' => 'authorization_code',
			'code_verifier' => $verifier,
		]);
		if (!isset($token['access_token']))
		{
			throw new GDO_Exception('err_google_token');
		}
		$profile = $this->requestJSON(self::USERINFO_URL, null, [
			'Authorization: Bearer ' . $token['access_token'],
		]);
		if (empty($profile['sub']) || empty($profile['email']) || empty($profile['email_verified']))
		{
			throw new GDO_Exception('err_google_profile');
		}
		return $profile;
	}

	/** @throws GDO_Exception */
	private function requestJSON(string $url, ?array $form = null, array $headers = []): array
	{
		$curl = curl_init($url);
		curl_setopt_array($curl, [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT => 15,
			CURLOPT_CONNECTTIMEOUT => 5,
			CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
			CURLOPT_SSL_VERIFYHOST => 2,
			CURLOPT_SSL_VERIFYPEER => true,
			CURLOPT_HTTPHEADER => $headers,
		]);
		if ($form !== null)
		{
			$headers[] = 'Content-Type: application/x-www-form-urlencoded';
			curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($form, '', '&', PHP_QUERY_RFC3986));
		}
		$body = curl_exec($curl);
		$status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
		curl_close($curl);
		if ($body === false || $status < 200 || $status >= 300 || !is_array($json = json_decode($body, true)))
		{
			throw new GDO_Exception('err_google_request');
		}
		return $json;
	}

	/** @throws GDO_Exception */
	public function resolveProfile(array $profile): GDO_User
	{
		$subject = (string)$profile['sub'];
		$email = strtolower((string)$profile['email']);
		$name = trim((string)($profile['name'] ?? ''));
		$picture = (string)($profile['picture'] ?? '');
		$identity = GDO_GoogleAuthIdentity::getBySubject($subject);
		if ($identity)
		{
			$user = GDO_User::getById($identity->getUserID());
			if (!$user)
			{
				throw new GDO_Exception('err_google_identity');
			}
		}
		else
		{
			$users = GDO_User::withSetting('Mail', 'email', $email);
			if (count($users) > 1)
			{
				throw new GDO_Exception('err_google_email');
			}
			$user = $users[0] ?? $this->createUser($subject, $email);
			if (GDO_GoogleAuthIdentity::getBy('gauth_user', $user->getID()))
			{
				throw new GDO_Exception('err_google_identity');
			}
			$identity = GDO_GoogleAuthIdentity::blank([
				'gauth_user' => $user->getID(),
				'gauth_subject' => $subject,
				'gauth_email' => $email,
			])->insert();
		}
		$identity->saveVars([
			'gauth_email' => $email,
			'gauth_name' => $name ?: null,
			'gauth_picture' => $picture ?: null,
		]);
		if ($name)
		{
			$user->saveSettingVar('GoogleAuth', 'google_real_name', $name);
			$user->saveVar('user_display_name', $name);
		}
		$this->importAvatar($user, $subject, $picture);
		return $user;
	}

	private function createUser(string $subject, string $email): GDO_User
	{
		$user = GDO_User::blank([
			'user_type' => GDT_UserType::MEMBER,
			'user_name' => $this->usernameFor($subject),
		])->insert();
		Module_Mail::instance()->saveUserSetting($user, 'email', $email);
		Module_Mail::instance()->saveUserSetting($user, 'email_confirmed', date('Y-m-d H:i:s'));
		GDT_Hook::callWithIPC('UserActivated', $user, null);
		return $user;
	}

	private function usernameFor(string $subject): string
	{
		$base = 'google-' . substr(hash('sha256', $subject), 0, 16);
		for ($i = 0; GDO_User::getByName($name = $base . ($i ? "-$i" : '')); $i++) {}
		return $name;
	}

	private function importAvatar(GDO_User $user, string $subject, string $picture): void
	{
		if (!$this->cfgImportAvatar() || !module_enabled('Avatar') || !$this->isGooglePicture($picture))
		{
			return;
		}
		$curl = curl_init($picture);
		curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_SSL_VERIFYPEER => true]);
		$data = curl_exec($curl);
		$status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
		curl_close($curl);
		if (is_string($data) && $status >= 200 && $status < 300 && strlen($data) <= 5_000_000)
		{
			GDO_UserAvatar::createAvatarFromString($user, "google-$subject.jpg", $data);
		}
	}

	private function isGooglePicture(string $url): bool
	{
		$host = strtolower((string)parse_url($url, PHP_URL_HOST));
		return str_starts_with($url, 'https://') && (str_ends_with($host, '.googleusercontent.com') || $host === 'googleusercontent.com');
	}
}
