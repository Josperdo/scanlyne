'use strict';

/**
 * Client-side form validation and UI interactivity for the Nmap Scanner GUI.
 *
 * You'll build three features here:
 *
 * 1. Scan form validation (initScanForm)
 *    - Get the form by ID: document.getElementById('scan-form')
 *    - Listen for the 'submit' event with addEventListener
 *    - Read input values, validate them, call event.preventDefault() to block bad submissions
 *    - Show error messages near the input that failed
 *
 * 2. Compare form validation (initCompareForm)
 *    - Get the compare form by ID: 'compare-form'
 *    - Ensure both dropdowns have a value selected
 *    - Ensure the two selected scans are different
 *
 * 3. Flash message dismiss (initFlashDismiss)
 *    - Select all elements with class 'flash': document.querySelectorAll('.flash')
 *    - Add a click listener to each that removes it from the DOM
 *
 * Useful DOM methods:
 *    document.getElementById('id')          → single element or null
 *    document.querySelectorAll('.class')     → NodeList of elements
 *    element.addEventListener('event', fn)  → attach event handler
 *    element.value                          → form input's current value
 *    element.remove()                       → remove element from DOM
 *    document.createElement('div')          → create a new element
 *    element.appendChild(child)             → add child to element
 *    element.textContent = 'text'           → set text safely (no XSS risk vs innerHTML)
 *    event.preventDefault()                 → stop form from submitting
 */

document.addEventListener('DOMContentLoaded', function () {

});

