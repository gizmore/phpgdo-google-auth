<?php
declare(strict_types=1);
namespace GDO\GoogleAuth;

use GDO\Core\GDO;
use GDO\Core\GDT_AutoInc;
use GDO\Core\GDT_CreatedAt;
use GDO\Core\GDT_EditedAt;
use GDO\Core\GDT_String;
use GDO\Mail\GDT_Email;
use GDO\Net\GDT_Url;
use GDO\User\GDT_User;

/** A verified Google OIDC subject bound to one local user. */
final class GDO_GoogleAuthIdentity extends GDO
{
	public static function getBySubject(string $subject): ?self
	{
		return self::getBy('gauth_subject', $subject);
	}

	public function getUserID(): string { return $this->gdoVar('gauth_user'); }

	public function gdoColumns(): array
	{
		return [
			GDT_AutoInc::make('gauth_id'),
			GDT_User::make('gauth_user')->notNull()->unique(),
			GDT_String::make('gauth_subject')->ascii()->caseS()->max(255)->notNull()->unique(),
			GDT_Email::make('gauth_email')->notNull(),
			GDT_String::make('gauth_name')->utf8()->max(191),
			GDT_Url::make('gauth_picture')->allowExternal()->max(2048),
			GDT_CreatedAt::make('gauth_created'),
			GDT_EditedAt::make('gauth_updated'),
		];
	}
}
