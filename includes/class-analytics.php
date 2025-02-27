<?php
/**
 * Newspack Analytics features.
 *
 * @package Newspack
 */

namespace Newspack;

defined( 'ABSPATH' ) || exit;

/**
 * Manages Analytics integrations.
 */
class Analytics {

	/**
	 * Events accumulated by block render callbacks.
	 *
	 * @var array
	 */
	public static $ntg_block_events = [];

	/**
	 * An integer to indicate the context a block is rendered in, e.g. content|overlay campaign|inline campaign.
	 *
	 * @var integer
	 */
	public static $block_render_context = 3;

	/**
	 * Constructor
	 */
	public function __construct() {
		add_filter( 'googlesitekit_gtag_opt', [ __CLASS__, 'set_extra_analytics_config_options' ] );
		add_action( 'wp_footer', [ __CLASS__, 'insert_gtag_amp_analytics' ] );

		add_action( 'wp_enqueue_scripts', [ __CLASS__, 'handle_custom_dimensions_reporting' ] );
		add_action( 'wp_footer', [ __CLASS__, 'inject_non_amp_events' ] );
		add_filter( 'render_block', [ __CLASS__, 'prepare_blocks_for_events' ], 10, 2 );
		add_action( 'newspack_campaigns_before_campaign_render', [ __CLASS__, 'set_campaign_render_context' ], 10, 1 );
		add_action( 'newspack_campaigns_after_campaign_render', [ __CLASS__, 'reset_render_context' ], 10, 1 );
		add_action( 'comment_form', [ __CLASS__, 'prepare_comment_events' ] );

		// WooCommerce hooks. https://docs.woocommerce.com/wc-apidocs/hook-docs.html.
		add_action( 'woocommerce_login_form_end', [ __CLASS__, 'prepare_login_events' ] );
		add_action( 'woocommerce_register_form_end', [ __CLASS__, 'prepare_registration_events' ] );
		add_action( 'woocommerce_after_checkout_registration_form', [ __CLASS__, 'prepare_checkout_registration_events' ] );

		// Reader Activation hooks.
		add_action( 'newspack_registered_reader', [ __CLASS__, 'newspack_registered_reader' ], 10, 5 );
		add_action( 'newspack_newsletters_add_contact', [ __CLASS__, 'newspack_newsletters_add_contact' ], 10, 4 );
	}

	/**
	 * Tell Site Kit to report the article's data as custom dimensions.
	 * More about custom dimensions: https://support.google.com/analytics/answer/2709828.
	 */
	public static function handle_custom_dimensions_reporting() {
		$custom_dimensions_values = self::get_custom_dimensions_values( get_the_ID() );
		foreach ( $custom_dimensions_values as $key => $value ) {
			self::add_custom_dimension_to_ga_config( $key, $value );
		}
	}

	/**
	 * Get values for custom dimensions to be sent to GA.
	 *
	 * @param string $post_id Post ID.
	 */
	public static function get_custom_dimensions_values( $post_id ) {
		$custom_dimensions        = Analytics_Wizard::list_configured_custom_dimensions();
		$custom_dimensions_values = [];
		foreach ( $custom_dimensions as $dimension ) {
			$dimension_role = $dimension['role'];
			// Remove `ga:` prefix.
			$dimension_id = substr( $dimension['gaID'], 3 );

			$post = get_post( $post_id );
			if ( $post ) {
				if ( 'category' === $dimension_role ) {
					$categories       = get_the_category( $post_id );
					$primary_category = get_post_meta( $post_id, '_yoast_wpseo_primary_category', true );
					if ( $primary_category ) {
						foreach ( $categories as $category ) {
							if ( $category->term_id === (int) $primary_category ) {
								$categories = [ $category ];
							}
						}
					}
					if ( ! empty( $categories ) ) {
						$categories_slugs                          = implode(
							',',
							array_map(
								function( $cat ) {
									return $cat->slug;
								},
								$categories
							)
						);
						$custom_dimensions_values[ $dimension_id ] = $categories_slugs;
					}
				}

				if ( 'author' === $dimension_role ) {
					$author_id                                 = $post->post_author;
					$custom_dimensions_values[ $dimension_id ] = get_the_author_meta( 'display_name', $author_id );
				}

				if ( 'word_count' === $dimension_role ) {
					$custom_dimensions_values[ $dimension_id ] = count( explode( ' ', wp_strip_all_tags( $post->post_content ) ) );
				}

				if ( 'publish_date' === $dimension_role ) {
					$custom_dimensions_values[ $dimension_id ] = get_the_time( 'Y-m-d H:i', $post->ID );
				}
			}
		}
		return $custom_dimensions_values;
	}

	/**
	 * Add custom dimension to GA config via Site Kit filters.
	 *
	 * @param string $dimension_id Dimension ID.
	 * @param string $payload Payload.
	 */
	public static function add_custom_dimension_to_ga_config( $dimension_id, $payload ) {
		// Non-AMP.
		add_filter(
			'googlesitekit_gtag_opt',
			function ( $gtag_opt ) use ( $payload, $dimension_id ) {
				$gtag_opt[ $dimension_id ] = $payload;
				return $gtag_opt;
			}
		);
		// AMP.
		add_filter(
			'googlesitekit_amp_gtag_opt',
			function ( $gtag_amp_opt ) use ( $payload, $dimension_id ) {
				$tracking_id = $gtag_amp_opt['vars']['gtag_id'];
				$gtag_amp_opt['vars']['config'][ $tracking_id ][ $dimension_id ] = $payload;
				return $gtag_amp_opt;
			}
		);
	}

	/**
	 * When a Newspack Campaign is being rendered, set the block rendering context based on whether campaign is inline or overlay.
	 *
	 * @param object $campaign The campaign object.
	 */
	public static function set_campaign_render_context( $campaign ) {
		$placement = isset( $campaign['options'], $campaign['options']['placement'] ) ? $campaign['options']['placement'] : null;
		switch ( $placement ) {
			case 'inline':
				self::$block_render_context = 1;
				break;
			default: // All other placement options are overlays.
				self::$block_render_context = 2;
				break;
		}
	}

	/**
	 * Reset rendering context after campaign rendering is complete.
	 *
	 * @param object $campaign The campaign object.
	 */
	public static function reset_render_context( $campaign ) {
		self::$block_render_context = 3;
	}

	/**
	 * Get a unique id.
	 *
	 * @return string Unique id.
	 */
	private static function get_uniqid() {
		return 'n' . substr( uniqid(), 10 );
	}

	/**
	 * Get data about all events.
	 *
	 * An event is largely based on the AMP analytics event spec and should contain the following fields:
	 *    'id'             => string Event ID (e.g. "popupFormDisplayed").
	 *    'on'             => string Type of action (e.g. "click" or "form-submit-success").
	 *    'amp_on'         => string Type of action for AMP if different (e.g. "amp-form-submit-success").
	 *    'element'        => string CSS selector for element (e.g. '#popup1').
	 *    'amp_element'    => string CSS selector for AMP version of element if different.
	 *    'event_name'     => string Name for event in GA (e.g. 'Clicked').
	 *    'event_label'    => string Label for event in GA (e.g. 'Popup 1')
	 *    'event_category' => string Category for event in GA (e.g. 'User Interaction').
	 * There can also be other fields specific for certain events (e.g. 'scrollSpec' for 'scroll' event listener).
	 */
	public static function get_events() {
		$events = [];
		if ( Analytics_Wizard::ntg_events_enabled() ) {
			$events = [
				[
					'id'             => self::get_uniqid(),
					'on'             => 'click',
					'element'        => 'a.share-facebook',
					'amp_element'    => 'amp-social-share[type="facebook"]',
					'event_name'     => 'social share',
					'event_label'    => 'facebook',
					'event_category' => 'NTG social',
				],
				[
					'id'             => self::get_uniqid(),
					'on'             => 'click',
					'element'        => 'a.share-twitter',
					'amp_element'    => 'amp-social-share[type="twitter"]',
					'event_name'     => 'social share',
					'event_label'    => 'twitter',
					'event_category' => 'NTG social',
				],
				[
					'id'             => self::get_uniqid(),
					'on'             => 'click',
					'element'        => 'a.share-jetpack-whatsapp',
					'amp_element'    => 'amp-social-share[type="whatsapp"]',
					'event_name'     => 'social share',
					'event_label'    => 'whatsapp',
					'event_category' => 'NTG social',
				],
				[
					'id'             => self::get_uniqid(),
					'on'             => 'click',
					'element'        => 'a.share-linkedin',
					'amp_element'    => 'amp-social-share[type="linkedin"]',
					'event_name'     => 'social share',
					'event_label'    => 'linkedin',
					'event_category' => 'NTG social',
				],
				[
					'id'             => self::get_uniqid(),
					'on'             => 'click',
					'element'        => 'a.share-reddit',
					'amp_element'    => 'amp-social-share[type="reddit"]',
					'event_name'     => 'social share',
					'event_label'    => 'reddit',
					'event_category' => 'NTG social',
				],
				[
					'id'             => self::get_uniqid(),
					'on'             => 'click',
					'element'        => 'a.share-telegram',
					'amp_element'    => 'amp-social-share[type="telegram"]',
					'event_name'     => 'social share',
					'event_label'    => 'telegram',
					'event_category' => 'NTG social',
				],
			];

			if ( ! is_front_page() && ! is_archive() ) {
				$events = array_merge(
					$events,
					[
						[
							'id'              => self::get_uniqid(),
							'on'              => 'scroll',
							'event_name'      => '25%',
							'event_value'     => 25,
							'event_label'     => get_the_title(),
							'event_category'  => 'NTG article milestone',
							'non_interaction' => true,
							'scrollSpec'      => [
								'verticalBoundaries' => [ 25 ],
							],
						],
						[
							'id'              => self::get_uniqid(),
							'on'              => 'scroll',
							'event_name'      => '50%',
							'event_value'     => 50,
							'event_label'     => get_the_title(),
							'event_category'  => 'NTG article milestone',
							'non_interaction' => true,
							'scrollSpec'      => [
								'verticalBoundaries' => [ 50 ],
							],
						],
						[
							'id'              => self::get_uniqid(),
							'on'              => 'scroll',
							'event_name'      => '100%',
							'event_value'     => 100,
							'event_label'     => get_the_title(),
							'event_category'  => 'NTG article milestone',
							'non_interaction' => true,
							'scrollSpec'      => [
								'verticalBoundaries' => [ 100 ],
							],
						],
					]
				);
			}
		}

		$custom_events = array_reduce(
			json_decode( get_option( Analytics_Wizard::$custom_events_option_name, '[]' ) ),
			function ( $all_custom_events, $event ) {
				$event = (array) $event;
				if ( $event['is_active'] ) {
					if ( 'submit' === $event['on'] ) {
						$event['amp_on'] = 'amp-form-submit-success';
					}
					if ( '' === $event['amp_element'] ) {
						unset( $event['amp_element'] );
					}
					$all_custom_events[] = $event;
				}
				return $all_custom_events;
			},
			[]
		);
		$events        = array_merge( $events, $custom_events );

		/**
		 * Other integrations can add events to track using this filter.
		 */
		return apply_filters( 'newspack_analytics_events', $events );
	}

	/**
	 * Alter block markup to support amp-analytics events.
	 *
	 * @param string $content The block content about to be appended.
	 * @param object $block The full block, including name and attributes.
	 */
	public static function prepare_blocks_for_events( $content, $block ) {
		if ( is_admin() ) {
			return $content;
		}

		switch ( $block['blockName'] ) {
			case 'jetpack/mailchimp':
				$content = self::prepare_jetpack_mailchimp_block( $content );
				break;
		}
		return $content;
	}

	/**
	 * Alter Jetpack Mailchimp block to support amp-analytics events.
	 *
	 * @param string $content The block content about to be appended.
	 */
	public static function prepare_jetpack_mailchimp_block( $content ) {
		$block_unique_id = self::get_uniqid();

		// Wrap the block in amp-layout to enable visibility tracking. Sugggested here: https://github.com/ampproject/amphtml/issues/11678.
		$content = sprintf( '<amp-layout id="%s">%s</amp-layout>', $block_unique_id, $content );

		self::$ntg_block_events[] = [
			'id'             => self::get_uniqid(),
			'amp_on'         => 'amp-form-submit-success',
			'on'             => 'submit',
			'element'        => '#' . $block_unique_id . ' form',
			'event_name'     => 'newsletter signup',
			'event_label'    => 'success',
			'event_category' => 'NTG newsletter',
			'visibilitySpec' => [
				'totalTimeMin' => 500,
			],
		];
		self::$ntg_block_events[] = [
			'id'              => self::get_uniqid(),
			'on'              => 'visible',
			'element'         => '#' . $block_unique_id,
			'event_name'      => 'newsletter modal impression ' . self::$block_render_context,
			'event_label'     => get_the_title(),
			'event_category'  => 'NTG newsletter',
			'non_interaction' => true,
			'visibilitySpec'  => [
				'totalTimeMin' => 500,
			],
		];
		return $content;
	}

	/**
	 * Prepare event triggers on user commenting.
	 */
	public static function prepare_comment_events() {
		self::$ntg_block_events[] = [
			'id'             => self::get_uniqid(),
			'amp_on'         => 'amp-form-submit-success',
			'on'             => 'submit',
			'element'        => '#commentform',
			'event_name'     => 'comment added',
			'event_category' => 'NTG user',
			'event_label'    => get_the_title(),
		];
	}

	/**
	 * Add login event triggers for the WooCommerce My Account and Checkout pages.
	 */
	public static function prepare_login_events() {
		self::$ntg_block_events[] = [
			'id'             => self::get_uniqid(),
			'amp-on'         => 'amp-form-submit-success',
			'on'             => 'submit',
			'element'        => '.woocommerce-form-login',
			'event_category' => 'NTG account',
			'event_name'     => 'login',
			'event_label'    => 'success',
		];
	}

	/**
	 * Add registration event triggers for the WooCommerce My Account page.
	 */
	public static function prepare_registration_events() {
		self::$ntg_block_events[] = [
			'id'             => self::get_uniqid(),
			'amp-on'         => 'amp-form-submit-success',
			'on'             => 'submit',
			'element'        => '.woocommerce-form-register',
			'event_category' => 'NTG account',
			'event_name'     => 'registration',
			'event_label'    => 'success',
		];
	}

	/**
	 * Add a registration event trigger for the WooCommerce Checkout page.
	 */
	public static function prepare_checkout_registration_events() {
		self::$ntg_block_events[] = [
			'id'             => self::get_uniqid(),
			'amp-on'         => 'amp-form-submit-success',
			'on'             => 'submit',
			'element'        => '.woocommerce-checkout',
			'event_category' => 'NTG account',
			'event_name'     => 'registration',
			'event_label'    => 'success',
		];
	}

	/**
	 * Filter the Google Analytics config options via Site Kit.
	 * Allows us to update or set additional config options for GA.
	 *
	 * @param array $gtag_opt gtag config options.
	 *
	 * @return array Filtered config options.
	 */
	public static function set_extra_analytics_config_options( $gtag_opt ) {
		if ( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() ) {
			return $gtag_opt;
		}

		if ( ! self::can_use_site_kits_analytics() ) {
			return $gtag_opt;
		}

		// Set transport type to 'beacon' to allow async requests to complete after a new page is loaded.
		// See: https://developers.google.com/analytics/devguides/collection/gtagjs/sending-data#specify_different_transport_mechanisms.
		$gtag_opt['transport_type'] = 'beacon';

		return $gtag_opt;
	}

	/**
	 * Insert amp-analytics tag/s into the footer of the page.
	 * The tag/s will contain the custom events to be sent to GA.
	 * This is to avoid the gtag endpoint limitation occuring with a single large config.
	 * More: https://github.com/ampproject/amphtml/issues/32911.
	 */
	public static function insert_gtag_amp_analytics() {
		$analytics = Google_Services_Connection::get_site_kit_analytics_module();
		if ( ! $analytics || ! $analytics->is_connected() ) {
			return;
		}
		$analytics_settings = $analytics->get_settings()->get();
		if ( ! isset( $analytics_settings['propertyID'] ) ) {
			return;
		}
		$tracking_id = $analytics_settings['propertyID'];

		// Config for amp-analytics.
		$config = [
			'optoutElementId' => '__gaOptOutExtension',
			'vars'            => [
				'gtag_id' => $tracking_id,
				'config'  => [
					$tracking_id => [
						'groups' => 'default',
						'linker' => [
							'domains' => [ wp_parse_url( home_url(), PHP_URL_HOST ) ],
						],
					],
				],
			],
		];

		// The Google Analytics User ID is used to associate multiple user sessions and activities with a unique ID.
		// See https://support.google.com/tagmanager/answer/4565987.
		if ( is_user_logged_in() ) {
			$config['vars']['user_id'] = get_current_user_id();
		}

		// Gather all custom events.
		$all_events = self::get_events();
		if ( Analytics_Wizard::ntg_events_enabled() ) {
			$all_events = array_merge( $all_events, self::$ntg_block_events );
		}
		$custom_events = [];
		foreach ( $all_events as $event ) {
			$event_config = [
				'request' => 'event',
				'on'      => isset( $event['amp_on'] ) ? $event['amp_on'] : $event['on'],
				'vars'    => [
					'event_name'     => $event['event_name'],
					'event_category' => $event['event_category'],
				],
			];
			if ( isset( $event['non_interaction'] ) && true === $event['non_interaction'] ) {
				$event_config['vars']['non_interaction'] = $event['non_interaction'];
			}
			if ( isset( $event['event_value'] ) ) {
				$event_config['vars']['value'] = $event['event_value'];
			}
			if ( isset( $event['event_label'] ) && ! empty( $event['event_label'] ) ) {
				$event_config['vars']['event_label'] = $event['event_label'];
			}

			if ( isset( $event['amp_element'] ) || isset( $event['element'] ) ) {
				$event_config['selector'] = isset( $event['amp_element'] ) ? $event['amp_element'] : $event['element'];
			}

			// Handle other config params e.g. 'scrollSpec'.
			foreach ( $event as $key => $val ) {
				if ( ! in_array( $key, [ 'id', 'on', 'amp_on', 'element', 'amp_element', 'event_name', 'event_label', 'event_category', 'is_active', 'non_interaction' ] ) ) {
					$event_config[ $key ] = $val;
				}
			}

			// Other integrations can use this filter if they need to modify the AMP-specific event config.
			$custom_events[] = [
				'id'     => $event['id'],
				'config' => apply_filters( 'newspack_analytics_amp_event_config', $event_config, $event ),
			];
		}

		if ( 0 === count( $custom_events ) ) {
			// Nothing to do here if no custom events are defined.
			return;
		}

		// Disable pageview reporting in this tag. Pageview is already handled by the tag
		// inserted by Site Kit.
		$tracking_id = $config['vars']['gtag_id'];
		$config['vars']['config'][ $tracking_id ]['send_page_view'] = false;

		// Divide the custom events into batches.
		$custom_events_batches = array_chunk( $custom_events, 10 );

		foreach ( $custom_events_batches as $events_batch ) {
			$config['triggers'] = [];
			foreach ( $events_batch as $event ) {
				$config['triggers'][ $event['id'] ] = $event['config'];
			}
			?>
				<amp-analytics type="gtag">
					<script type="application/json">
						<?php echo wp_json_encode( $config ); ?>
					</script>
				</amp-analytics>
			<?php
		}
	}

	/**
	 * Can we rely on Site Kit's Analytics module?
	 */
	private static function can_use_site_kits_analytics() {
		$sitekit_manager = Configuration_Managers::configuration_manager_class_for_plugin_slug( 'google-site-kit' );
		return $sitekit_manager->is_module_active( 'analytics' )
		// If Google Tag Manager module is active, it supersedes the Analytics module.
		// This means that effectively GTM module being active equals Analytics module being inactive.
		&& false === $sitekit_manager->is_module_active( 'tagmanager' );
	}

	/**
	 * Inject event listeners on non-AMP pages.
	 */
	public static function inject_non_amp_events() {
		if ( function_exists( 'is_amp_endpoint' ) && is_amp_endpoint() ) {
			return;
		}

		if ( ! self::can_use_site_kits_analytics() ) {
			return;
		}

		// Discard events with duplicate ids.
		$all_events   = array_merge( self::get_events(), self::$ntg_block_events );
		$unique_array = [];
		foreach ( $all_events as $element ) {
			$hash                  = $element['id'];
			$unique_array[ $hash ] = $element;
		}

		foreach ( $unique_array as $event ) {
			ob_start();
			switch ( $event['on'] ) {
				case 'click':
					self::output_js_click_event( $event );
					break;
				case 'scroll':
					self::output_js_scroll_event( $event );
					break;
				case 'submit':
					self::output_js_submit_event( $event );
					break;
				case 'visible':
					self::output_js_visible_event( $event );
					break;
				case 'ini-load':
					self::output_js_ini_load_event( $event );
					break;
				default:
					break;
			}

			// Other integrations can use this filter if they need to add a custom JS event handler.
			$event_js = apply_filters( 'newspack_analytics_event_js', ob_get_clean(), $event );
			echo $event_js; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
	}

	/**
	 * Output JS for a click-based event listener.
	 *
	 * @param array $event Event info. See 'get_events'.
	 */
	protected static function output_js_click_event( $event ) {
		?>
		<script>
			( function() {
				var elementSelector = '<?php echo str_replace( '&quot;', '"', esc_attr( $event['element'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Allow quotes for CSS selectors validity. ?>';
				var elements        = Array.prototype.slice.call( document.querySelectorAll( elementSelector ) );

				for ( var i = 0; i < elements.length; ++i ) {
					elements[i].addEventListener( 'click', function( event ) {
						<?php // Ensure the clicked element still matches the selector. For example an aria attribue might've changed. ?>
						if (event.currentTarget.matches(elementSelector)) {
							gtag(
								'event',
								'<?php echo esc_attr( $event['event_name'] ); ?>',
								{
									event_category: '<?php echo esc_attr( $event['event_category'] ); ?>',
									<?php if ( isset( $event['event_label'] ) ) : ?>
										event_label: '<?php echo esc_attr( $event['event_label'] ); ?>',
									<?php endif; ?>
								}
							);
						};
					} );
				}
			} )();
		</script>
		<?php
	}

	/**
	 * Output JS for a scroll-based event listener.
	 *
	 * @param array $event Event info. See 'get_events'.
	 */
	protected static function output_js_scroll_event( $event ) {
		?>
		<script>
			( function() {
				var scrollPercent = <?php echo (int) $event['scrollSpec']['verticalBoundaries'][0]; ?>;

				var eventSent = false;
				var reportEvent = function(){
					if ( eventSent ) {
						window.removeEventListener( 'scroll', reportEvent );
						return;
					}

					var scrollPos = ( window.pageYOffset || window.scrollY ) + window.innerHeight;
					var documentHeight = document.body.clientHeight;

					if ( ( ( scrollPos / documentHeight ) * 100 ) >= scrollPercent ) {
						eventSent = true;
						gtag(
							'event',
							'<?php echo esc_attr( $event['event_name'] ); ?>',
							{
								event_category: '<?php echo esc_attr( $event['event_category'] ); ?>',
								<?php if ( isset( $event['event_label'] ) ) : ?>
									event_label: '<?php echo esc_attr( $event['event_label'] ); ?>',
								<?php endif; ?>
								value: scrollPercent,
								non_interaction: <?php echo esc_attr( ! empty( $event['non_interaction'] ) && true === $event['non_interaction'] ? 'true' : 'false' ); ?>,
							}
						);
					}
				}
				// Fire initially - page might be loaded with scroll offset.
				window.addEventListener( 'DOMContentLoaded', reportEvent );
				window.addEventListener( 'scroll', reportEvent );
			} )();
		</script>
		<?php
	}

	/**
	 * Output JS for a form submit-based event listener.
	 *
	 * @param array $event Event info. See 'get_events'.
	 */
	protected static function output_js_submit_event( $event ) {
		?>
		<script>
			( function() {
				var elementSelector = '<?php echo esc_attr( $event['element'] ); ?>';
				var elements        = Array.prototype.slice.call( document.querySelectorAll( elementSelector ) );

				for ( var i = 0; i < elements.length; ++i ) {
					elements[i].addEventListener( 'submit', function(e) {
						var eventInfo = {
								event_category: '<?php echo esc_attr( $event['event_category'] ); ?>'
						};
						<?php if ( isset( $event['event_label'] ) ) : ?>
							var form = e.currentTarget;
							var eventLabel = '<?php echo isset( $event['event_label'] ) ? esc_attr( $event['event_label'] ) : ''; ?>';
							<?php if ( preg_match( '/(\${formId}|\${formFields\[(.*?)\]})/', $event['event_label'] ) ) : ?>
								eventLabel = eventLabel.replace( '${formId}', form.id );
								var fields = eventLabel.match( /\${formFields\[(.*?)\]}/g )
								fields.forEach( function( field ) {
									var fieldName = field.match( /\${formFields\[(.*?)\]}/ )[1];
									if ( form[ fieldName ] ) {
										var fieldValues = [];
										if ( form[ fieldName ].length ) {
											for ( var j = 0; j < form[ fieldName ].length; j++ ) {
												if ( form[ fieldName ][ j ].checked ) {
													fieldValues.push( form[ fieldName ][ j ].value );
												}
											}
										} else {
											fieldValues.push( form[ fieldName ].value );
										}

										eventLabel = eventLabel.replace( field, fieldValues.join( ',' ) );
									}
								} );
							<?php endif; ?>
							eventInfo.event_label = eventLabel;
						<?php endif; ?>

						gtag(
							'event',
							'<?php echo esc_attr( $event['event_name'] ); ?>',
							eventInfo
						);
					} );
				}
			} )();
		</script>
		<?php
	}

	/**
	 * Output JS for a form visibility-based event listener.
	 *
	 * @param array $event Event info. See 'get_events'.
	 */
	protected static function output_js_visible_event( $event ) {
		$delay = ! empty( $event['visibilitySpec'] ) && ! empty( $event['visibilitySpec']['totalTimeMin'] ) ? $event['visibilitySpec']['totalTimeMin'] : 0;
		?>
		<script>
			( function() {
				window.newspackViewedElements = window.newspackViewedElements || [];
				window.newspackCheckVisibility = window.newspackCheckVisibility || function( el ) {
					var elementHeight = el.offsetHeight;
					var elementWidth = el.offsetWidth;

					if ( elementHeight === 0 || elementWidth === 0 ) {
						return false;
					}

					var rect = el.getBoundingClientRect();

					return (
						rect.top >= -elementHeight &&
						rect.left >= -elementWidth &&
						rect.right <= ( window.innerWidth || document.documentElement.clientWidth ) + elementWidth &&
						rect.bottom <= ( window.innerHeight || document.documentElement.clientHeight ) + elementHeight
					)
				};

				var elementSelector = '<?php echo $event['element']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>';
				var elements        = Array.prototype.slice.call( document.querySelectorAll( elementSelector ) );

				var reportEvent = function() {
					for ( var i = 0; i < elements.length; ++i ) {
						var elementToCheck = elements[i];

						// Stop tracking scroll after visibility has been reported.
						if ( -1 !== window.newspackViewedElements.indexOf( elementToCheck ) ) {
							window.removeEventListener( 'scroll', reportEvent );
							return;
						}

						if ( window.newspackCheckVisibility( elementToCheck ) && -1 === window.newspackViewedElements.indexOf( elementToCheck ) ) {
							window.newspackViewedElements.push( elementToCheck );

							var totalTimeMin = window.setTimeout( function() {

								// If element is still in viewport after <?php echo esc_attr( $delay ); ?>ms
								if ( window.newspackCheckVisibility( elementToCheck ) ) {
									return gtag(
										'event',
										'<?php echo esc_attr( $event['event_name'] ); ?>',
										{
											event_category: '<?php echo esc_attr( $event['event_category'] ); ?>',
											<?php if ( isset( $event['event_label'] ) ) : ?>
												event_label: '<?php echo esc_attr( $event['event_label'] ); ?>',
											<?php endif; ?>
											non_interaction: <?php echo esc_attr( ! empty( $event['non_interaction'] ) && true === $event['non_interaction'] ? 'true' : 'false' ); ?>,
										}
									);
								}
								window.clearTimeout( totalTimeMin );
							}, <?php echo esc_attr( $delay ); ?> );
						}
					}
				};

				// Fire initially - page might be loaded with scroll offset.
				window.addEventListener( 'DOMContentLoaded', reportEvent );
				window.addEventListener( 'scroll', reportEvent );
			} )();
		</script>
		<?php
	}

	/**
	 * Output JS for a load event listener.
	 *
	 * @param array $event Event info. See 'get_events'.
	 */
	protected static function output_js_ini_load_event( $event ) {
		$element = isset( $event['element'] ) ? $event['element'] : '';
		?>
		<script>
			( function() {
				var handleEvent = function() {
					gtag(
						'event',
						'<?php echo esc_attr( $event['event_name'] ); ?>',
						{
							event_category: '<?php echo esc_attr( $event['event_category'] ); ?>',
							<?php if ( isset( $event['event_label'] ) ) : ?>
								event_label: '<?php echo esc_attr( $event['event_label'] ); ?>',
							<?php endif; ?>
							non_interaction: <?php echo esc_attr( ! empty( $event['non_interaction'] ) && true === $event['non_interaction'] ? 'true' : 'false' ); ?>,
						}
					);
				};

				var elementSelector = '<?php echo esc_attr( $element ); ?>';
				if (elementSelector) {
					var elements = Array.prototype.slice.call( document.querySelectorAll( elementSelector ) );
					for ( var i = 0; i < elements.length; ++i ) {

						var observer = new MutationObserver(function(mutations) {
							mutations.forEach(function(mutation) {
								if (
									mutation.attributeName === 'amp-access-hide' &&
									mutation.type == "attributes" &&
									! mutation.target.hasAttribute('amp-access-hide')
								) {
									handleEvent()
								}
							});
						});

						observer.observe(elements[i], { attributes: true });
					}
				} else {
					window.addEventListener('DOMContentLoaded', handleEvent)
				}
			} )();
		</script>
		<?php
	}

	/**
	 * When a new reader registers, sent an event to GA.
	 *
	 * @param string         $email         Email address.
	 * @param bool           $authenticate  Whether to authenticate after registering.
	 * @param false|int      $user_id       The created user id.
	 * @param false|\WP_User $existing_user The existing user object.
	 * @param array          $metadata      Metadata.
	 */
	public static function newspack_registered_reader( $email, $authenticate, $user_id, $existing_user, $metadata ) {
		if ( $existing_user ) {
			return;
		}
		$event_spec = [
			'category' => __( 'Newspack Reader Activation', 'newspack' ),
			'action'   => __( 'Registration', 'newspack' ),
		];

		if ( isset( $metadata['registration_method'] ) ) {
			$event_spec['action'] .= ' (' . $metadata['registration_method'] . ')';
		}

		if ( isset( $metadata['lists'] ) ) {
			$event_spec['label'] = __( 'Signed up for lists:', 'newspack' ) . ' ' . implode( ', ', $metadata['lists'] );
		}

		if ( isset( $metadata['current_page_url'] ) ) {
			$parsed_url = \wp_parse_url( $metadata['current_page_url'] );
			if ( $parsed_url ) {
				if ( isset( $parsed_url['host'] ) ) {
					$event_spec['host'] = $parsed_url['host'];
				}
				if ( isset( $parsed_url['path'] ) ) {
					$event_spec['path'] = $parsed_url['path'];
				}
			}
		}

		\Newspack\Google_Services_Connection::send_custom_event( $event_spec );

		if ( Analytics_Wizard::ntg_events_enabled() ) {
			\Newspack\Google_Services_Connection::send_custom_event(
				[
					'category' => __( 'NTG account', 'newspack' ),
					'action'   => __( 'registration', 'newspack' ),
					'label'    => 'success',
				]
			);
		}
	}

	/**
	 * When a reader signs up for the newsletter, send an event to GA.
	 *
	 * @param string         $provider The provider name.
	 * @param array          $contact  {
	 *    Contact information.
	 *
	 *    @type string   $email                 Contact email address.
	 *    @type string   $name                  Contact name. Optional.
	 *    @type string   $existing_contact_data Existing contact data, if updating a contact. The hook will be also called when
	 *    @type string[] $metadata              Contact additional metadata. Optional.
	 * }
	 * @param string[]|false $lists    Array of list IDs to subscribe the contact to.
	 * @param bool|WP_Error  $result   True if the contact was added or error if failed.
	 */
	public static function newspack_newsletters_add_contact( $provider, $contact, $lists, $result ) {
		if (
			! Analytics_Wizard::ntg_events_enabled()
			|| ! method_exists( '\Newspack_Newsletters_Subscription', 'get_contact_data' )
			// Don't send events for updates to a contact.
			|| $contact['existing_contact_data']
		) {
			return;
		}

		// If the user is only being subscribed to the master list, they did not sign up for the newsletter explicitly.
		$lists = Newspack_Newsletters::get_lists_without_active_campaign_master_list( $lists );
		if ( empty( $lists ) ) {
			return;
		}

		\Newspack\Google_Services_Connection::send_custom_event(
			[
				'category' => __( 'NTG newsletter', 'newspack' ),
				'action'   => __( 'newsletter signup', 'newspack' ),
				'label'    => 'success',
			]
		);
	}
}
new Analytics();
