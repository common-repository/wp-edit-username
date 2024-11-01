<?php

add_action( 'wp_ajax_wpeu_update_user_name', 'wpeu_update_user_name' );

function wpeu_update_user_name()
{
    if( ! current_user_can( 'edit_users' ) ) die();

    if ( isset( $_POST['wp_edit_username_nonce'] ) && wp_verify_nonce( $_POST['wp_edit_username_nonce'], 'wp_edit_username_action' ) )
    {
        $new_username       = sanitize_user( $_POST['new_username'] );
        
        $current_username   = sanitize_user( $_POST['current_username'] );

        $response           = array();

        $to                 = array();

        // ---------------------------------------------------------
        // check if new_username is empty
        // ---------------------------------------------------------
        if( empty( $new_username ) || empty( $current_username ) )
        {
            $response['alert_message'] = __( 'Username Can Not be Empty!', 'wp-edit-username' );
            
            wp_send_json( $response ); die();
        }

        // ---------------------------------------------------------
        // Check if username consists invalid illegal character
        // ---------------------------------------------------------
        if( ! validate_username( $new_username ) )
        {
            $response['alert_message'] = __( 'Username can not have illegal characters', 'wp-edit-username' );
            
            wp_send_json( $response ); die();
        }

        // ---------------------------------------------------------
        // Filters the list of blacklisted usernames.
        //
        // @https://developer.wordpress.org/reference/hooks/illegal_user_logins/
        // ---------------------------------------------------------
        $illegal_user_logins = array_map( 'strtolower', (array) apply_filters( 'illegal_user_logins', array() ) );

        if ( in_array( $new_username, $illegal_user_logins ) )
        {
            $response['alert_message'] =  __( 'Sorry, that username is not allowed.', 'wp-edit-username' );
            
            wp_send_json( $response ); die();
        }

        // ---------------------------------------------------------
        // If $new_username already registered
        // ---------------------------------------------------------
        if( username_exists( $new_username ) )
        {
            $response['alert_message'] =  __( 'Sorry, that username already exists and not available.', 'wp-edit-username' );
            
            wp_send_json( $response ); die();
        }

        global $wpdb;

        // ---------------------------------------------------------
        // Change / Update Username With old one
        // ---------------------------------------------------------
        $query  = $wpdb->prepare( "UPDATE $wpdb->users SET user_login = %s WHERE user_login = %s", $new_username, $current_username );
        
        $result = $wpdb->query( $query );

        $options = get_option( 'wpeu_register_settings_fields' );

        if ( $result > 0 )
        {
            $response['success_message'] =  sprintf( 'Username Updated from <code>%s</code> to <code>%s</code>.', $current_username, $new_username );

            if ( isset( $options['wpeu_send_email_field'] ) && $options['wpeu_send_email_field'] == 'on' )
            {
                $user_email = $wpdb->get_var( $wpdb->prepare( "SELECT user_email FROM $wpdb->users WHERE user_login = %s", $new_username ) );

                if ( isset( $options['wpeu_email_receiver_field'] ) )
                {                       
                    if ( $options['wpeu_email_receiver_field'] == 'user_only' )
                    {    
                        $to         = array( sanitize_email( $user_email ) );
                    }
                    elseif ( $options['wpeu_email_receiver_field'] == 'admin_only' )
                    {    
                        $to         = array();
                        
                        $admins     = get_users( 'role=Administrator' );
                        
                        foreach ( $admins as $admin )
                        {
                            $to[]   = sanitize_email( $admin->user_email );
                        }
                    }
                    elseif ( $options['wpeu_email_receiver_field'] == 'admin_user' )
                    {
                        $to         = array( sanitize_email( $user_email ) );
                        
                        $admins     = get_users( 'role=Administrator' );
                        
                        foreach ( $admins as $admin )
                        {
                            $to[]   = sanitize_email( $admin->user_email );
                        }
                    }
                }

                $subject = apply_filters( 'wp_username_changed_email_subject', $subject = $options['wpeu_email_subject_field'], $old_username, $new_username );

                $body    = apply_filters( 'wp_username_changed_email_body', $body = $options['wpeu_email_body_field'], $old_username, $new_username );

                $user    = get_user_by( 'login', $new_username );
        
                if( $user )
                {
                    $body = str_replace( [ '{{first_name}}', '{{last_name}}', '{{display_name}}', '{{full_name}}', '{{old_username}}', '{{new_username}}' ], [ $user->first_name, $user->last_name, $user->display_name, $user->first_name . ' ' . $user->last_name, $current_username, $new_username ], $body );
                }

                $headers = array( 'Content-Type: text/html; charset=UTF-8' );

                foreach ( $to as $email )
                {
                    wp_mail( $email, $subject, $body, $headers );
                }
            }
        }

        // ---------------------------------------------------------
        // Change / Update nicename if == username
        // ---------------------------------------------------------
        $query = $wpdb->prepare( "UPDATE $wpdb->users SET user_nicename = %s WHERE user_login = %s AND user_nicename = %s", $new_username, $new_username, $current_username );
        
        $wpdb->query( $query );

        // ---------------------------------------------------------
        // Change / Update display name if == username
        // ---------------------------------------------------------
        $query  = $wpdb->prepare( "UPDATE $wpdb->users SET display_name = %s WHERE user_login = %s AND display_name = %s", $new_username, $new_username, $current_username );
        
        $wpdb->query( $query );

        // ---------------------------------------------------------
        // Update Username on Multisite
        // ---------------------------------------------------------
        if( is_multisite() )
        {
            $super_admins = (array) get_site_option( 'site_admins', array( 'admin' ) );
            
            $array_key = array_search( $current_username, $super_admins );

            if( $array_key )
            {
                $super_admins[ $array_key ] = $new_username;
            }
            
            update_site_option( 'site_admins' , $super_admins );
        }
    }
    else
    {
        $response['alert_message'] =  __( 'Nonce verification failed.', 'wp-edit-username' );
    }

    wp_send_json( $response ); die();
}