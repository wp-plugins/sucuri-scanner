<?php

/**
 * Admin JavaScript and Stylesheet registration
 *
 **** This script file was kindly donated to Sucuri by the awesome Brandon Dove - https://twitter.com/brandondove ****
 *
 * Hooks into the admin_enqueue_scripts action to register scripts and styles that
 * are needed throughout the plugin back-end
 */
add_action( 'admin_enqueue_scripts', 'sucuriscan_admin_script_style_registration', 1 );
function sucuriscan_admin_script_style_registration() {

	$default_deps = array( 'jquery' );

echo 'tacos';

	/*
	 * REGISTER JAVASCRIPT FILES
	 * 01. Authorization
	/****************************************************************************************************************************/
	$scripts = array();

	// 1. AUTHORIZATION
	$scripts['sucuri-authorization'] = array(
		sucuriscan_JS. SUCURI_URL . 'inc/js/authorization.js',
		$default_deps,
		sucuriscan_VERSION,
		true );

	// Register all of our scripts for later use
	foreach( $scripts as $slug => $script )
		wp_register_script( $slug, $script[0], $script[1], $script[2], $script[3] );


	/*
	 * REGISTER CSS FILES
	 * 01. Authorization
	/****************************************************************************************************************************/
	$styles = array();

	// 1. AUTHORIZATION
	$styles['sucuri-setup'] = array(
		sucuriscan_CSS.'setup.css',
		array( 'sucuri-ads-common', 'wp-pointer' ),
		sucuriscan_VERSION,
		'screen' );

	// Register all of our styles for later use
	foreach( $styles as $slug => $style )
		wp_register_style( $slug, $style[0], $style[1], $style[2], $style[3] );
}


/**
 * Public JavaScript and Stylesheet registration
 *
 * Hooks into the wp_enqueue_scripts action to register scripts and styles that
 * are needed on the front end
 */
add_action( 'wp_enqueue_scripts', 'sucuriscan_public_script_style_registration', 1 );
function sucuriscan_public_script_style_registration() {

	/*
	 * REGISTER CSS FILES
	 * 01. Tracking Filters
	/****************************************************************************************************************************/
	$styles = array();

	// 1. DEFAULT AD CSS
	$styles['sucuri-default-css'] = array(
		sucuriscan_CSS.'widget-default.css',
		false,
		sucuriscan_VERSION,
		'screen' );

	// Register all of our styles for later use
	foreach( $styles as $slug => $style )
		wp_register_style( $slug, $style[0], $style[1], $style[2], $style[3] );
}
