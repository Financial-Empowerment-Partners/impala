package com.payala.impala.demo.ui.main

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.payala.impala.demo.R
import com.payala.impala.demo.databinding.ActivityMainBinding

/**
 * Main screen with a [BottomNavigationView] hosting three tabs:
 * Cards (start destination), Transfers, and Settings.
 *
 * Uses Jetpack Navigation with a [NavHostFragment] defined in
 * `activity_main.xml`. The toolbar title updates automatically when the
 * user switches tabs.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)

        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController

        binding.bottomNav.setupWithNavController(navController)

        navController.addOnDestinationChangedListener { _, destination, _ ->
            binding.toolbar.title = destination.label
        }
    }
}
