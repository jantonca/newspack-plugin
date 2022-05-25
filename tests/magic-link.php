<?php
/**
 * Tests the Magic Link functionality.
 *
 * @package Newspack\Tests
 */

use Newspack\Magic_Link;

/**
 * Tests the Magic Link functionality.
 */
class Newspack_Test_Magic_Link extends WP_UnitTestCase {
	/**
	 * Reader user id.
	 *
	 * @var int
	 */
	private static $user_id = null;

	/**
	 * Setup for the tests.
	 */
	public function setUp() {
		// Enable reader activation.
		add_filter( 'newspack_reader_activation_enabled', '__return_true' );

		// Disable magic link cookie for the tests.
		add_filter( 'newspack_magic_link_use_cookie', '__return_false' );

		// Create sample reader.
		if ( empty( $user_id ) ) {
			$user_id = Reader_Activation::register_reader( self::$reader_email, self::$reader_name );
		}
	}

	/**
	 * Assert valid token.
	 *
	 * @param array $token_data Token data. {
	 *   The token data.
	 *
	 *   @type string $token  The token.
	 *   @type string $client Client hash.
	 *   @type string $time   Token creation time.
	 * }
	 */
	public function assertToken( $token_data ) {
		$this->assertIsString( $token_data['token'] );
		$this->assertIsString( $token_data['client'] );
		$this->assertIsInt( $token_data['time'] );
	}

	/**
	 * Test token generation.
	 */
	public function test_generate_token() {
		$token_data = Magic_Link::generate_token( self::$user_id );
		$this->assertToken( $token_data );
	}

	/**
	 * Test token validation.
	 */
	public function test_validate_token() {
		$token_data = Magic_Link::generate_token( self::$user_id );
		$this->assertToken( Magic_Link::validate_token( self::$user_id, $token_data['token'], $token_data['client'] ) );
	}

	/**
	 * Test error when attempting to generate for admin user.
	 */
	public function test_generate_token_for_admin() {
		$admin_id   = wp_insert_user(
			[
				'user_login' => 'sample-admin',
				'user_pass'  => wp_generate_password(),
				'user_email' => 'test@test.com',
				'role'       => 'administrator',
			]
		);
		$token_data = Magic_Link::generate_token( $admin_id );
		$this->assertTrue( is_wp_error( $token_data ) );
		$this->assertEquals( 'newspack_magic_link_invalid_user', $token_data->get_error_code() );
		wp_delete_user( $admin_id ); // Clean up.
	}
}
