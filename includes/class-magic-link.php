<?php
/**
 * Newspack Magic Links functionality.
 *
 * @package Newspack
 */

namespace Newspack;

defined( 'ABSPATH' ) || exit;

/**
 * Newspack Magic Links class.
 */
final class Magic_Link {

	const FORM_ACTION = 'np_magic_link';

	const USER_META = 'np_magic_link_tokens';

	const COOKIE = 'np_magic_link';

	/**
	 * Current session secret.
	 *
	 * @var string
	 */
	private static $session_secret = '';

	/**
	 * Initialize hooks.
	 */
	public static function init() {
		\add_action( 'init', [ __CLASS__, 'wp_cli' ] );
		\add_action( 'clear_auth_cookie', [ __CLASS__, 'clear_cookie' ] );
		\add_action( 'set_auth_cookie', [ __CLASS__, 'clear_cookie' ] );
		\add_action( 'template_redirect', [ __CLASS__, 'process_token_request' ] );
	}

	/**
	 * Get magic link token expiration period.
	 *
	 * @return int Expiration in seconds.
	 */
	private static function get_token_expiration_period() {
		/**
		 * Filters the duration of the magic link token expiration period.
		 *
		 * @param int    $length Duration of the expiration period in seconds.
		 */
		return \apply_filters( 'newspack_magic_link_token_expiration', 30 * MINUTE_IN_SECONDS );
	}

	/**
	 * Clear magic link cookie.
	 */
	public static function clear_cookie() {
		/** This filter is documented in wp-includes/pluggable.php */
		if ( ! apply_filters( 'send_auth_cookies', true ) ) {
			return;
		}

		// phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.cookies_setcookie
		setcookie( self::COOKIE, ' ', time() - YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN );
	}

	/**
	 * Get the session client secret for magic link hash validation.
	 *
	 * @param bool $reset Whether to generate a new secret.
	 */
	private static function get_client_secret( $reset = false ) {
		$secret = self::$session_secret;

		/** Fetch cookie if available. */
		if ( empty( $secret ) && isset( $_COOKIE[ self::COOKIE ] ) ) {
		  // phpcs:ignore WordPressVIPMinimum.Variables.RestrictedVariables.cache_constraints___COOKIE
			$secret = \sanitize_text_field( \wp_unslash( $_COOKIE[ self::COOKIE ] ) );
		}

		/** Regenerate if empty or resetting. */
		if ( empty( $secret ) || true === $reset ) {
			$secret = \wp_generate_password( 43, false, false );
		}

		self::$session_secret = $secret;

		/** This filter is documented in wp-includes/pluggable.php */
		if ( \apply_filters( 'send_auth_cookies', true ) ) {
		  // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.cookies_setcookie
			setcookie( self::COOKIE, $secret, time() + self::get_token_expiration_period(), COOKIEPATH, COOKIE_DOMAIN, true );
		}

		return $secret;
	}

	/**
	 * Get the session client hash.
	 *
	 * @param bool $reset_secret Whether to reset the stored client secret.
	 *
	 * @return string|null Client hash or null if unable to generate one.
	 */
	private static function get_client_hash( $reset_secret = false ) {
		if ( defined( 'WP_CLI' ) ) {
			return null;
		}

		$hash_args = [];

		// phpcs:ignore WordPressVIPMinimum.Variables.ServerVariables.UserControlledHeaders, WordPressVIPMinimum.Variables.RestrictedVariables.cache_constraints___SERVER__REMOTE_ADDR__
		if ( isset( $_SERVER['REMOTE_ADDR'] ) && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			// phpcs:ignore WordPressVIPMinimum.Variables.ServerVariables.UserControlledHeaders, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPressVIPMinimum.Variables.RestrictedVariables.cache_constraints___SERVER__REMOTE_ADDR__
			$hash_args['ip'] = \wp_unslash( $_SERVER['REMOTE_ADDR'] );
		}
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) && ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPressVIPMinimum.Variables.RestrictedVariables.cache_constraints___SERVER__HTTP_USER_AGENT__
			$hash_args['user_agent'] = \wp_unslash( $_SERVER['HTTP_USER_AGENT'] );
		}

		/**
		 * Filters whether to use a locally stored secret as a client hash argument.
		 *
		 * @param bool $use_cookie Whether to use a locally stored secret as a client hash argument.
		 */
		if ( true === \apply_filters( 'newspack_magic_link_use_secret', true ) ) {
			$hash_args['secret'] = self::get_client_secret( $reset_secret );
		}

		/**
		 * Filters the client hash arguments for the current session.
		 *
		 * @param string[] $hash_args Client hash arguments.
		 */
		$hash_args = \apply_filters( 'newspack_magic_link_client_hash_args', $hash_args );

		return ! empty( $hash_args ) ? sha1( implode( '', $hash_args ) ) : null;
	}

	/**
	 * Generate magic link token.
	 *
	 * @param \WP_User $user User to generate the magic link token for.
	 *
	 * @return array|\WP_Error {
	 *   Magic link token data.
	 *
	 *   @type string $token  The token.
	 *   @type string $client Origin IP hash.
	 *   @type string $time   Token creation time.
	 * }
	 */
	public static function generate_token( $user ) {
		if ( ! Reader_Activation::is_user_reader( $user ) ) {
			return new \WP_Error( 'newspack_magic_link_invalid_user', __( 'User is not a reader.', 'newspack' ) );
		}
		$now    = time();
		$tokens = \get_user_meta( $user->ID, self::USER_META, true );
		if ( empty( $tokens ) ) {
			$tokens = [];
		}

		$expire = $now - self::get_token_expiration_period();
		if ( ! empty( $tokens ) ) {
			/** Limit maximum tokens to 5. */
			$tokens = array_slice( $tokens, -4, 4 );
			/** Clear expired tokens. */
			foreach ( $tokens as $index => $token_data ) {
				if ( $token_data['time'] < $expire ) {
					unset( $tokens[ $index ] );
				}
			}
			$tokens = array_values( $tokens );
		}

		/** Generate the new token. */
		$token      = sha1( \wp_generate_password() );
		$client     = self::get_client_hash( true );
		$token_data = [
			'token'  => $token,
			'client' => ! empty( $client ) ? $client : '',
			'time'   => $now,
		];
		$tokens[]   = $token_data;
		\update_user_meta( $user->ID, self::USER_META, $tokens );
		return $token_data;
	}

	/**
	 * Generate a magic link.
	 *
	 * @param \WP_User $user User to generate the magic link for.
	 * @param string   $url  Destination url. Default is home_url().
	 *
	 * @return string|\WP_Error Magic link url or WP_Error if token generation failed.
	 */
	private static function generate_url( $user, $url = '' ) {
		$token_data = self::generate_token( $user );
		if ( \is_wp_error( $token_data ) ) {
			return $token_data;
		}
		return \add_query_arg(
			[
				'action' => self::FORM_ACTION,
				'uid'    => $user->ID,
				'token'  => $token_data['token'],
			],
			! empty( $url ) ? $url : \home_url()
		);
	}

	/**
	 * Get a magic link email arguments given a user.
	 *
	 * @param \WP_User $user User to generate the magic link for.
	 *
	 * @return array|\WP_Error $email Email arguments or error. {
	 *   Used to build wp_mail().
	 *
	 *   @type string $to      The intended recipient - New user email address.
	 *   @type string $subject The subject of the email.
	 *   @type string $message The body of the email.
	 *   @type string $headers The headers of the email.
	 * }
	 */
	public static function generate_email( $user ) {
		if ( ! Reader_Activation::is_user_reader( $user ) ) {
			return new \WP_Error( 'newspack_magic_link_invalid_user', __( 'User is not a reader.', 'newspack' ) );
		}

		$magic_link_url = self::generate_url( $user );

		if ( \is_wp_error( $magic_link_url ) ) {
			return $magic_link_url;
		}

		$blogname = \wp_specialchars_decode( \get_option( 'blogname' ), ENT_QUOTES );

		$switched_locale = \switch_to_locale( \get_user_locale( $user ) );

		/* translators: %s: Site title. */
		$message  = sprintf( __( 'Welcome back to %s!', 'newspack' ), $blogname ) . "\r\n\r\n";
		$message .= __( 'Authenticate your account by visiting the following address:', 'newspack' ) . "\r\n\r\n";
		$message .= $magic_link_url . "\r\n";

		$email = [
			'to'      => $user->user_email,
			/* translators: %s Site title. */
			'subject' => __( '[%s] Authentication link', 'newspack' ),
			'message' => $message,
			'headers' => '',
		];

		if ( $switched_locale ) {
			\restore_previous_locale();
		}

		/**
		 * Filters the magic link email.
		 *
		 * @param array    $email          Email arguments. {
		 *   Used to build wp_mail().
		 *
		 *   @type string $to      The intended recipient - New user email address.
		 *   @type string $subject The subject of the email.
		 *   @type string $message The body of the email.
		 *   @type string $headers The headers of the email.
		 * }
		 * @param \WP_User $user           User to send the magic link to.
		 * @param string   $magic_link_url Magic link url.
		 */
		return \apply_filters( 'newspack_magic_link_email', $email, $user, $magic_link_url );
	}

	/**
	 * Send magic link email to reader.
	 *
	 * @param \WP_User $user User to send the magic link to.
	 *
	 * @return bool|\WP_Error Whether the email was sent or WP_Error if sending failed.
	 */
	public static function send_email( $user ) {
		$email = self::generate_email( $user );

		if ( \is_wp_error( $email ) ) {
			return $email;
		}

		$blogname = \wp_specialchars_decode( \get_option( 'blogname' ), ENT_QUOTES );

		// phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.wp_mail_wp_mail
		$sent = \wp_mail(
			$email['to'],
			\wp_specialchars_decode( sprintf( $email['subject'], $blogname ) ),
			$email['message'],
			$email['headers']
		);

		return $sent;
	}

	/**
	 * Verify and returns the valid token given a user, token and client.
	 * 
	 * This method cleans up expired tokens and returns the token data for
	 * immediate use.
	 *
	 * @param int    $user_id User ID.
	 * @param string $client  Client hash.
	 * @param string $token   Token to verify.
	 *
	 * @return array|\WP_Error {
	 *   Token data.
	 *
	 *   @type string $token  The token.
	 *   @type string $client Client hash.
	 *   @type string $time   Token creation time.
	 * }
	 */
	public static function validate_token( $user_id, $client, $token ) {
		$errors = new \WP_Error();
		$user   = \get_user_by( 'id', $user_id );

		if ( ! $user ) {
			$errors->add( 'invalid_user', __( 'User not found.', 'newspack' ) );
		} elseif ( ! Reader_Activation::is_user_reader( $user ) ) {
			$errors->add( 'invalid_user_type', __( 'Not allowed for this user', 'newspack' ) );
		} else {
			$tokens = \get_user_meta( $user->ID, self::USER_META, true );
			if ( empty( $tokens ) || empty( $token ) ) {
				$errors->add( 'invalid_token', __( 'Invalid token.', 'newspack' ) );
			}
		}

		$valid_token = false;

		if ( ! $errors->has_errors() ) {
			$expire = time() - self::get_token_expiration_period();

			foreach ( $tokens as $index => $token_data ) {
				if ( $token_data['time'] < $expire ) {
					unset( $tokens[ $index ] );

				} elseif ( $token_data['token'] === $token ) {
					$valid_token = $token_data;

					/** If token data has a client hash, it must be equal to the user's. */
					if ( ! empty( $token_data['client'] ) && $token_data['client'] !== $client ) {
						$errors->add( 'invalid_client', __( 'Invalid client.', 'newspack' ) );
					}

					unset( $tokens[ $index ] );
					break;
				}
			}

			if ( empty( $valid_token ) ) {
				$errors->add( 'expired_token', __( 'Token has expired.', 'newspack' ) );
			}
			self::clear_cookie();

			$tokens = array_values( $tokens );
			\update_user_meta( $user->ID, self::USER_META, $tokens );
		}

		return $errors->has_errors() ? $errors : $valid_token;
	}

	/**
	 * Handle a reader authentication attempt using magic link token.
	 *
	 * @param int    $user_id User ID.
	 * @param string $token   Token to authenticate.
	 *
	 * @return bool|\WP_Error Whether the user was authenticated or WP_Error.
	 */
	private static function authenticate( $user_id, $token ) {
		if ( \is_user_logged_in() ) {
			return false;
		}

		$client     = self::get_client_hash();
		$token_data = self::validate_token( $user_id, $client, $token );

		if ( \is_wp_error( $token_data ) ) {
			return $token_data;
		}

		if ( empty( $token_data ) ) {
			return false;
		}

		$user = \get_user_by( 'id', $user_id );

		if ( ! $user ) {
			return new \WP_Error( 'invalid_user', __( 'User not found.', 'newspack' ) );
		}

		Reader_Activation::set_reader_verified( $user );
		Reader_Activation::set_current_reader( $user->ID );

		/**
		 * Fires after a reader has been authenticated via magic link.
		 *
		 * @param \WP_User $user User that has been authenticated.
		 */
		do_action( 'newspack_magic_link_authenticated', $user );

		return true;
	}

	/**
	 * Process magic link token from request.
	 */
	public static function process_token_request() {
		if ( ! Reader_Activation::is_enabled() ) {
			return;
		}
		if ( \is_user_logged_in() ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['action'] ) || self::FORM_ACTION !== $_GET['action'] ) {
			return;
		}
		if ( ! isset( $_GET['token'] ) || ! isset( $_GET['uid'] ) ) {
			\wp_die( \esc_html__( 'Invalid request.', 'newspack' ) );
		}

		$user_id = \absint( \wp_unslash( $_GET['uid'] ) );
		$token   = \sanitize_text_field( \wp_unslash( $_GET['token'] ) );
		// phpcs:enable

		$authenticated = self::authenticate( $user_id, $token );

		if ( \is_wp_error( $authenticated ) ) {
			/** Do not disclose error messages. */
			\wp_die( \esc_html__( 'We were not able to authenticate through this link.', 'newspack' ) );
		}

		\wp_safe_redirect( \remove_query_arg( [ 'action', 'uid', 'token' ] ) );
		exit;
	}

	/**
	 * WP CLI Commands.
	 */
	public static function wp_cli() {
		if ( ! defined( 'WP_CLI' ) ) {
			return;
		}
		if ( ! Reader_Activation::is_enabled() ) {
			return;
		}

		/**
		 * Send a magic link to a reader, given their email address or user ID.
		 *
		 * Usage: wp newspack magic-link send john@doe.com
		 */
		$send = function( $args, $assoc_args ) {
			if ( ! isset( $args[0] ) ) {
				\WP_CLI::error( 'Please provide a user email or ID.' );
			}
			$id_or_email = $args[0];
			if ( absint( $id_or_email ) ) {
				$user = \get_user_by( 'id', $id_or_email );
			} else {
				$user = \get_user_by( 'email', $id_or_email );
			}
			if ( ! $user || is_wp_error( $user ) ) {
				\WP_CLI::error( __( 'User not found.', 'newspack' ) );
			}
			$result = self::send_email( $user );
			if ( \is_wp_error( $result ) ) {
				\WP_CLI::error( $result->get_error_message() );
			}
			// translators: %s is the email address of the user.
			\WP_CLI::success( sprintf( __( 'Email sent to %s.', 'newspack' ), $user->user_email ) );
		};
		\WP_CLI::add_command(
			'newspack magic-link send',
			$send,
			[
				'shortdesc' => __( 'Send a magic link to a reader.', 'newspack' ),
			]
		);
	}
}
Magic_Link::init();
