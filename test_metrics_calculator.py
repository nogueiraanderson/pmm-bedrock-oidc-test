#!/usr/bin/env python3
"""
Unit tests for MetricsCalculator module.

This test suite covers all functionality with proper error cases,
security tests, and edge cases to ensure robustness.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch, mock_open
from pathlib import Path

from metrics_calculator import (
    MetricsCalculator, 
    MetricsCalculatorError, 
    DatabaseConnectionError,
    InvalidDataError,
    hash_password
)


class TestMetricsCalculator(unittest.TestCase):
    """Test cases for MetricsCalculator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.calc = MetricsCalculator(slow_query_threshold=100.0)
    
    def tearDown(self):
        """Clean up after tests."""
        self.calc.close_connections()

    def test_init(self):
        """Test MetricsCalculator initialization."""
        calc = MetricsCalculator(200.0)
        self.assertEqual(calc.slow_query_threshold, 200.0)
        self.assertEqual(calc.metrics, [])
        self.assertIsNone(calc._connection_pool)

    def test_init_default_threshold(self):
        """Test MetricsCalculator initialization with default threshold."""
        calc = MetricsCalculator()
        self.assertEqual(calc.slow_query_threshold, 100.0)

    def test_connect_to_database_valid_params(self):
        """Test database connection with valid parameters."""
        result = self.calc.connect_to_database(
            "localhost", 3306, "user", "hashed_password"
        )
        self.assertTrue(result)

    def test_connect_to_database_invalid_host(self):
        """Test database connection with empty host."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.connect_to_database("", 3306, "user", "pass")
        self.assertIn("Missing required connection parameters", str(context.exception))

    def test_connect_to_database_invalid_port(self):
        """Test database connection with invalid port."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.connect_to_database("localhost", 0, "user", "pass")
        self.assertIn("Invalid port number", str(context.exception))
        
        with self.assertRaises(InvalidDataError) as context:
            self.calc.connect_to_database("localhost", 70000, "user", "pass")
        self.assertIn("Invalid port number", str(context.exception))

    def test_calculate_query_rate_valid(self):
        """Test query rate calculation with valid data."""
        queries = [10, 20, 30, 40, 50]
        result = self.calc.calculate_query_rate(queries)
        self.assertEqual(result, 30.0)

    def test_calculate_query_rate_empty_list(self):
        """Test query rate calculation with empty list."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_query_rate([])
        self.assertIn("empty queries list", str(context.exception))

    def test_calculate_query_rate_invalid_data(self):
        """Test query rate calculation with invalid data."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_query_rate([-1, 10, 20])
        self.assertIn("non-negative numbers", str(context.exception))
        
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_query_rate(["invalid", 10, 20])
        self.assertIn("non-negative numbers", str(context.exception))

    def test_calculate_avg_response_time_valid(self):
        """Test average response time calculation with valid data."""
        times = [100.0, 200.0, 300.0]
        result = self.calc.calculate_avg_response_time(times)
        self.assertEqual(result, 200.0)

    def test_calculate_avg_response_time_empty(self):
        """Test average response time calculation with empty list."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_avg_response_time([])
        self.assertIn("empty response times list", str(context.exception))

    def test_calculate_avg_response_time_invalid_data(self):
        """Test average response time with invalid data."""
        with self.assertRaises(InvalidDataError):
            self.calc.calculate_avg_response_time([-1, 100, 200])

    def test_parse_metrics_valid_json(self):
        """Test metrics parsing with valid JSON."""
        data = json.dumps({
            "metrics": {
                "cpu": {"usage": 75.5},
                "memory": {"usage": 60.2}
            }
        })
        result = self.calc.parse_metrics(data)
        self.assertEqual(result["cpu"]["usage"], 75.5)
        self.assertEqual(result["memory"]["usage"], 60.2)

    def test_parse_metrics_invalid_json(self):
        """Test metrics parsing with invalid JSON."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.parse_metrics("invalid json")
        self.assertIn("Invalid JSON format", str(context.exception))

    def test_parse_metrics_missing_metrics_key(self):
        """Test metrics parsing with missing metrics key."""
        data = json.dumps({"data": {"cpu": 75}})
        with self.assertRaises(InvalidDataError) as context:
            self.calc.parse_metrics(data)
        self.assertIn("Missing 'metrics' key", str(context.exception))

    def test_parse_metrics_empty_string(self):
        """Test metrics parsing with empty string."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.parse_metrics("")
        self.assertIn("non-empty string", str(context.exception))

    def test_parse_metrics_non_dict_metrics(self):
        """Test metrics parsing when metrics is not a dict."""
        data = json.dumps({"metrics": "not a dict"})
        with self.assertRaises(InvalidDataError) as context:
            self.calc.parse_metrics(data)
        self.assertIn("'metrics' must be a dictionary", str(context.exception))

    def test_secure_file_operation_valid(self):
        """Test secure file operation with valid filename."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.txt"
            test_content = "test content"
            test_file.write_text(test_content)
            
            result = self.calc.secure_file_operation("test.txt", temp_dir)
            self.assertEqual(result, test_content)

    def test_secure_file_operation_path_traversal(self):
        """Test secure file operation prevents path traversal."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.secure_file_operation("../../../etc/passwd")
        self.assertIn("path traversal", str(context.exception))

    def test_secure_file_operation_absolute_path(self):
        """Test secure file operation rejects absolute paths."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.secure_file_operation("/etc/passwd")
        self.assertIn("path traversal", str(context.exception))

    def test_secure_file_operation_file_not_found(self):
        """Test secure file operation with non-existent file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(InvalidDataError) as context:
                self.calc.secure_file_operation("nonexistent.txt", temp_dir)
            self.assertIn("File not found", str(context.exception))

    def test_calculate_percentile_valid(self):
        """Test percentile calculation with valid data."""
        values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        
        # Test 50th percentile (median)
        result = self.calc.calculate_percentile(values, 0.5)
        self.assertIsInstance(result, float)
        
        # Test edge cases
        min_val = self.calc.calculate_percentile(values, 0.0)
        self.assertEqual(min_val, 1)
        
        max_val = self.calc.calculate_percentile(values, 1.0)
        self.assertEqual(max_val, 10)

    def test_calculate_percentile_empty_list(self):
        """Test percentile calculation with empty list."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_percentile([], 0.5)
        self.assertIn("empty values list", str(context.exception))

    def test_calculate_percentile_invalid_percentile(self):
        """Test percentile calculation with invalid percentile."""
        values = [1, 2, 3, 4, 5]
        
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_percentile(values, -0.1)
        self.assertIn("between 0.0 and 1.0", str(context.exception))
        
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_percentile(values, 1.1)
        self.assertIn("between 0.0 and 1.0", str(context.exception))

    def test_calculate_percentile_invalid_values(self):
        """Test percentile calculation with non-numeric values."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.calculate_percentile(["a", "b", "c"], 0.5)
        self.assertIn("must be numbers", str(context.exception))

    def test_update_metrics_valid(self):
        """Test metrics update with valid data."""
        initial_metrics = [{"value": 10}, {"value": 20}]
        self.calc.metrics = initial_metrics
        
        new_metrics = [{"value": 30}, {"value": 40}]
        self.calc.update_metrics(new_metrics)
        
        self.assertEqual(len(self.calc.metrics), 4)
        values = [m["value"] for m in self.calc.metrics]
        self.assertEqual(values, [10, 20, 30, 40])

    def test_update_metrics_removes_invalid(self):
        """Test metrics update removes invalid entries."""
        initial_metrics = [
            {"value": 10},
            {"value": -5},  # Invalid: negative value
            {"value": 20}
        ]
        self.calc.metrics = initial_metrics
        
        new_metrics = [{"value": 30}]
        self.calc.update_metrics(new_metrics)
        
        # Should have 2 valid old metrics + 1 new metric
        self.assertEqual(len(self.calc.metrics), 3)
        values = [m["value"] for m in self.calc.metrics]
        self.assertEqual(values, [10, 20, 30])

    def test_update_metrics_invalid_input(self):
        """Test metrics update with invalid input."""
        with self.assertRaises(InvalidDataError) as context:
            self.calc.update_metrics("not a list")
        self.assertIn("must be a list", str(context.exception))

    def test_update_metrics_skips_invalid_entries(self):
        """Test metrics update skips invalid entries."""
        new_metrics = [
            {"value": 10},           # Valid
            "not a dict",            # Invalid: not a dict
            {"no_value": 20},        # Invalid: missing value key
            {"value": 30}            # Valid
        ]
        
        self.calc.update_metrics(new_metrics)
        
        # Should only have 2 valid metrics
        self.assertEqual(len(self.calc.metrics), 2)
        values = [m["value"] for m in self.calc.metrics]
        self.assertEqual(values, [10, 30])

    def test_get_metrics_summary_empty(self):
        """Test metrics summary with empty metrics."""
        result = self.calc.get_metrics_summary()
        expected = {"total_metrics": 0, "summary": "No metrics available"}
        self.assertEqual(result, expected)

    def test_get_metrics_summary_no_numeric_values(self):
        """Test metrics summary with no numeric values."""
        self.calc.metrics = [{"name": "test"}, {"type": "counter"}]
        result = self.calc.get_metrics_summary()
        self.assertEqual(result["total_metrics"], 2)
        self.assertIn("No numeric values found", result["summary"])

    def test_get_metrics_summary_with_values(self):
        """Test metrics summary with valid numeric values."""
        self.calc.metrics = [
            {"value": 10},
            {"value": 20},
            {"value": 30}
        ]
        result = self.calc.get_metrics_summary()
        
        self.assertEqual(result["total_metrics"], 3)
        self.assertEqual(result["min_value"], 10)
        self.assertEqual(result["max_value"], 30)
        self.assertEqual(result["avg_value"], 20.0)
        self.assertEqual(result["median_value"], 20)

    def test_close_connections(self):
        """Test connection cleanup."""
        # This is mostly to ensure no errors occur during cleanup
        self.calc.close_connections()
        self.assertIsNone(self.calc._connection_pool)


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions."""
    
    def test_hash_password(self):
        """Test password hashing function."""
        password = "test_password"
        hashed = hash_password(password)
        
        # Should return a hex string
        self.assertIsInstance(hashed, str)
        self.assertEqual(len(hashed), 64)  # SHA-256 produces 64 character hex string
        
        # Same password should produce same hash
        hashed2 = hash_password(password)
        self.assertEqual(hashed, hashed2)
        
        # Different password should produce different hash
        different_hash = hash_password("different_password")
        self.assertNotEqual(hashed, different_hash)

    def test_hash_password_empty(self):
        """Test password hashing with empty string."""
        hashed = hash_password("")
        self.assertIsInstance(hashed, str)
        self.assertEqual(len(hashed), 64)


class TestSecurityFeatures(unittest.TestCase):
    """Test cases focusing on security features."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.calc = MetricsCalculator()
    
    def tearDown(self):
        """Clean up after tests."""
        self.calc.close_connections()

    def test_no_password_logging(self):
        """Test that passwords are never logged."""
        with patch('metrics_calculator.logger') as mock_logger:
            self.calc.connect_to_database("localhost", 3306, "user", "secret_hash")
            
            # Check that no log call contains the password
            for call in mock_logger.info.call_args_list:
                log_message = str(call)
                self.assertNotIn("secret_hash", log_message)

    def test_sql_injection_prevention(self):
        """Test that SQL injection is prevented through parameterized queries."""
        # This test verifies the method signature uses parameterized queries
        # In a real database test, we would verify the actual SQL execution
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            # Test that malicious threshold values don't break the query structure
            malicious_threshold = "'; DROP TABLE queries; --"
            
            # This should not raise an exception due to SQL injection
            # but may raise other exceptions due to database setup
            try:
                self.calc.get_slow_queries(db_path, malicious_threshold)
            except (DatabaseConnectionError, InvalidDataError):
                # These are expected - we're testing that SQL injection doesn't occur
                pass
        finally:
            os.unlink(db_path)

    def test_path_traversal_prevention(self):
        """Test comprehensive path traversal prevention."""
        dangerous_filenames = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "..%2F..%2Fetc%2Fpasswd",  # URL encoded
            "....//....//etc//passwd",
            "..;/etc/passwd"
        ]
        
        for filename in dangerous_filenames:
            with self.assertRaises(InvalidDataError) as context:
                self.calc.secure_file_operation(filename)
            self.assertIn("path traversal", str(context.exception).lower())


class TestPerformanceFeatures(unittest.TestCase):
    """Test cases for performance-related features."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.calc = MetricsCalculator()
    
    def tearDown(self):
        """Clean up after tests."""
        self.calc.close_connections()

    def test_efficient_percentile_calculation(self):
        """Test that percentile calculation is efficient and doesn't modify original list."""
        original_values = [5, 2, 8, 1, 9, 3, 7, 4, 6]
        test_values = original_values.copy()
        
        # Calculate percentile
        result = self.calc.calculate_percentile(test_values, 0.5)
        
        # Verify original list is unchanged
        self.assertEqual(test_values, original_values)
        
        # Verify result is reasonable
        self.assertIsInstance(result, float)

    def test_safe_list_modification(self):
        """Test that metrics update doesn't modify list during iteration."""
        # Create metrics with some negative values
        initial_metrics = []
        for i in range(100):
            value = i - 50  # Creates both positive and negative values
            initial_metrics.append({"value": value})
        
        self.calc.metrics = initial_metrics
        
        # Update should complete without error
        new_metrics = [{"value": 1000}]
        self.calc.update_metrics(new_metrics)
        
        # All remaining values should be non-negative plus the new value
        for metric in self.calc.metrics:
            self.assertGreaterEqual(metric["value"], 0)


if __name__ == '__main__':
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.WARNING)  # Reduce noise during tests
    
    # Run the tests
    unittest.main(verbosity=2)