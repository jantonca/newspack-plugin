<?php
/**
 * Newspack Wizards manager.
 *
 * @package Newspack
 */

namespace Newspack;

defined( 'ABSPATH' ) || exit;

/**
 * Manages the wizards.
 */
class Wizards {

	/**
	 * Information about all of the wizards.
	 * See `init` for structure of the data.
	 *
	 * @var array
	 */
	protected static $wizards = [];

	/**
	 * Initialize and register all of the wizards.
	 */
	public static function init() {
		self::$wizards = [
			'setup'                     => new Setup_Wizard(),
			'dashboard'                 => new Dashboard(),
			'reader-revenue-onboarding' => new Reader_Revenue_Onboarding_Wizard(),
			'donations'                 => new Donations_Wizard(),
			'subscriptions'             => new Subscriptions_Wizard(),
			'google-adsense'            => new Google_AdSense_Wizard(),
			'google-ad-manager'         => new Google_Ad_Manager_Wizard(),
			'google-analytics'          => new Google_Analytics_Wizard(),
			'components-demo'           => new Components_Demo(),
			'performance'               => new Performance_Wizard(),
		];
	}

	/**
	 * Get a wizard's object.
	 *
	 * @param string $wizard_slug The wizard to get. Use slug from self::$wizards.
	 * @return Wizard | bool The wizard on success, false on failure.
	 */
	public static function get_wizard( $wizard_slug ) {
		if ( isset( self::$wizards[ $wizard_slug ] ) ) {
			return self::$wizards[ $wizard_slug ];
		}

		return false;
	}

	/**
	 * Get a wizard's URL.
	 *
	 * @param string $wizard_slug The wizard to get URL for. Use slug from self::$wizards.
	 * @return string | bool The URL on success, false on failure.
	 */
	public static function get_url( $wizard_slug ) {
		$wizard = self::get_wizard( $wizard_slug );
		if ( $wizard ) {
			return $wizard->get_url();
		}

		return false;
	}

	/**
	 * Get all the URLs for all the wizards.
	 *
	 * @return array of slug => URL pairs.
	 */
	public static function get_urls() {
		$urls = [];
		foreach ( self::$wizards as $slug => $wizard ) {
			$urls[ $slug ] = $wizard->get_url();
		}

		return $urls;
	}

	/**
	 * Get a wizard's name.
	 *
	 * @param string $wizard_slug The wizard to get name for. Use slug from self::$wizards.
	 * @return string | bool The name on success, false on failure.
	 */
	public static function get_name( $wizard_slug ) {
		$wizard = self::get_wizard( $wizard_slug );
		if ( $wizard ) {
			return $wizard->get_name();
		}

		return false;
	}

	/**
	 * Get a wizard's description.
	 *
	 * @param string $wizard_slug The wizard to get description for. Use slug from self::$wizards.
	 * @return string | bool The description on success, false on failure.
	 */
	public static function get_description( $wizard_slug ) {
		$wizard = self::get_wizard( $wizard_slug );
		if ( $wizard ) {
			return $wizard->get_description();
		}

		return false;
	}

	/**
	 * Get whether a wizard is completed.
	 *
	 * @param string $wizard_slug The wizard to get completion for. Use slug from self::$wizards.
	 * @return bool True if completed. False otherwise.
	 */
	public static function is_completed( $wizard_slug ) {
		$wizard = self::get_wizard( $wizard_slug );
		if ( $wizard ) {
			return $wizard->is_completed();
		}

		return false;
	}
}
Wizards::init();
