<?php
/**
 * Piwik - free/libre analytics platform
 *
 * @link http://piwik.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */
namespace Piwik\Plugins\LoginRevokable;

use Exception;
use Piwik\Container\StaticContainer;
use Piwik\Plugin\Manager;
use Piwik\Plugins\Login\Login;
use Piwik\Db;
use Piwik\Common;
use Piwik\FrontController;

class LoginRevokable extends \Piwik\Plugin
{
    public function getListHooksRegistered()
    {
        return array(
            'Request.initAuthenticationObject' => 'initAuthenticationObject',
            'User.isNotAuthorized'             => 'noAccess',
            'API.Request.authenticate'         => 'ApiRequestAuthenticate',
        );
    }

    public function install()
    {
        try {
            $sql = "CREATE TABLE " . Common::prefixTable('revokable_auth') . " (
                        auth_token VARCHAR( 10 ) NOT NULL ,
                        auth_user VARCHAR( 100 ) NOT NULL ,
			auth_last TIMESTAMP NOT NULL,
                        PRIMARY KEY ( auth_token, auth_user )
                    )  DEFAULT CHARSET=utf8 ";
            Db::exec($sql);
        } catch (Exception $e) {
            // ignore error if table already exists (1050 code is for 'table already exists')
            if (!Db::get()->isErrNo($e, '1050')) {
                throw $e;
            }
        }
    }

    /**
     * Deactivate default Login module, as both cannot be activated together
     */
    public function activate()
    {
        if (Manager::getInstance()->isPluginActivated("Login") == true) {
            Manager::getInstance()->deactivatePlugin("Login");
        }
    }

    public function uninstall()
    {
        Db::dropTables(Common::prefixTable('revokable_auth'));
    }
    /**
     * Activate default Login module, as one of them is needed to access Piwik
     */
    public function deactivate()
    {
        if (Manager::getInstance()->isPluginActivated("Login") == false) {
            Manager::getInstance()->activatePlugin("Login");
        }
    }

    public function initAuthenticationObject($activateCookieAuth = false)
    {
        $auth = new Auth();
        StaticContainer::getContainer()->set('Piwik\Auth', $auth);

        $login = new Login();
        return $login->initAuthenticationFromCookie($auth, $activateCookieAuth);
    }

    public function ApiRequestAuthenticate($tokenAuth)
    {
        $login = new Login();
        return $login->ApiRequestAuthenticate($tokenAuth);
    }

    public function noAccess(Exception $exception)
    {
        $exceptionMessage = $exception->getMessage();

        echo FrontController::getInstance()->dispatch('LoginRevokable', 'login', array($exceptionMessage));
    }
}
