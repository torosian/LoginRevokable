<?php
/**
 * Piwik - free/libre analytics platform
 *
 * @link http://piwik.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */
namespace Piwik\Plugins\LoginRevokable;

use Piwik\AuthResult;
use Piwik\DB;
use Piwik\Plugins\Login;
use Piwik\Plugins\UsersManager\Model;
use Piwik\Session;
use Piwik\Session\SessionNamespace;
use Piwik\Common;
use Piwik\Config;
use Piwik\Cookie;

class Auth extends \Piwik\Plugins\Login\Auth
{
    private static $session = null;

    /**
     * @var Model
     */
    private $userModel;

    /**
     * Constructor.
     *
     * @param Model|null $userModel
     */
    public function __construct(Model $userModel = null)
    {
        if ($userModel === null) {
            $userModel = new Model();
        }

        $this->userModel = $userModel;
    }

    /**
     * Authentication module's name
     *
     * @return string
     */
    public function getName()
    {
        return 'LoginRevokable';
    }

    /**
     * Authenticates user
     *
     * @return \Piwik\AuthResult
     */
    public function authenticate()
    {
	$session = self::getSession();

        if (empty(static::$session->auth2) && $this->login != "" && $this->md5Password != "") {
            static::$session->auth2 = mt_rand();
	    Db::get()->query("INSERT INTO " . Common::prefixTable("revokable_auth") . " SET auth_user = ?, auth_token = ?, auth_last = NOW()", array($this->login, static::$session->auth2));
        }

	$revokableToken = Db::get()->fetchAssoc("SELECT * FROM " . Common::prefixTable("revokable_auth") . " WHERE auth_token = ?", array(static::$session->auth2));
	
	if(count($revokableToken) == 0) {
	  static::$session->auth2 = null;
	}

	$return = parent::authenticate();

	if(empty(static::$session->auth2) && $return->getIdentity() != 'anonymous') {
	  $authCookieName = Config::getInstance()->General['login_cookie_name'];
          $cookie = new Cookie($authCookieName);
          $cookie->delete();
	  Session::expireSessionCookie();
	  $result = new AuthResult(AuthResult::FAILURE, $this->login, null);
	  return $result;
	}

	return $return;
    }

    private static function getSession()
    {
        if (!isset(static::$session)) {
            static::$session = new SessionNamespace('revokable_auth');
        }

        return static::$session;
    }
}

