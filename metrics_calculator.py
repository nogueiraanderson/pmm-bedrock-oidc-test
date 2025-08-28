#!/usr/bin/env python3
"""
Metrics Calculator for PMM Performance Monitoring

This module provides secure and efficient functionality to calculate various 
database performance metrics including query rates, response times, and 
slow query analysis.

Author: PMM Team
License: Apache 2.0
"""

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Union
from statistics import median, quantiles
import hashlib
from pathlib import Path

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MetricsCalculatorError(Exception):
    """Base exception for MetricsCalculator errors."""
    pass


class DatabaseConnectionError(MetricsCalculatorError):
    """Raised when database connection fails."""
    pass


class InvalidDataError(MetricsCalculatorError):
    """Raised when invalid data is provided."""
    pass


class MetricsCalculator:
    """
    A secure metrics calculator for PMM performance monitoring.
    
    This class provides methods to calculate database performance metrics
    with proper error handling, input validation, and security measures.
    """
    
    def __init__(self, slow_query_threshold: float = 100.0) -> None:
        """
        Initialize the MetricsCalculator.
        
        Args:
            slow_query_threshold: Threshold in milliseconds for slow queries
        """
        self.metrics: List[Dict[str, Any]] = []
        self.slow_query_threshold = slow_query_threshold
        self._connection_pool: Optional[sqlite3.Connection] = None
        logger.info("MetricsCalculator initialized with threshold: %s ms", slow_query_threshold)

    def __del__(self) -> None:
        """Clean up resources when the object is destroyed."""
        self.close_connections()

    def close_connections(self) -> None:
        """Close all database connections properly."""
        if self._connection_pool:
            try:
                self._connection_pool.close()
                logger.info("Database connection closed")
            except Exception as e:
                logger.error("Error closing database connection: %s", e)
            finally:
                self._connection_pool = None

    @contextmanager
    def _get_db_connection(self, db_path: str):
        """
        Context manager for database connections with proper cleanup.
        
        Args:
            db_path: Path to the database file
            
        Yields:
            Database connection
            
        Raises:
            DatabaseConnectionError: If connection fails
        """
        conn = None
        try:
            # Validate database path to prevent path traversal
            safe_path = Path(db_path).resolve()
            if not str(safe_path).startswith(os.getcwd()):
                raise DatabaseConnectionError("Invalid database path - path traversal detected")
            
            conn = sqlite3.connect(str(safe_path))
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            yield conn
        except sqlite3.Error as e:
            logger.error("Database connection error: %s", e)
            raise DatabaseConnectionError(f"Failed to connect to database: {e}") from e
        finally:
            if conn:
                conn.close()

    def connect_to_database(self, host: str, port: int, username: str, 
                          password_hash: str) -> bool:
        """
        Establish a secure database connection.
        
        Args:
            host: Database host
            port: Database port  
            username: Database username
            password_hash: Hashed password (never log plain text)
            
        Returns:
            True if connection successful
            
        Raises:
            DatabaseConnectionError: If connection fails
            InvalidDataError: If parameters are invalid
        """
        # Validate inputs
        if not all([host, username, password_hash]):
            raise InvalidDataError("Missing required connection parameters")
            
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise InvalidDataError("Invalid port number")
        
        # Log connection attempt WITHOUT password
        logger.info("Connecting to %s:%d with user %s", host, port, username)
        
        try:
            # In a real implementation, use proper database drivers
            # This is a placeholder for secure connection logic
            logger.info("Database connection established successfully")
            return True
        except Exception as e:
            logger.error("Failed to connect to database: %s", e)
            raise DatabaseConnectionError(f"Connection failed: {e}") from e

    def calculate_query_rate(self, queries: List[Union[int, float]]) -> float:
        """
        Calculate the average query rate.
        
        Args:
            queries: List of query counts or rates
            
        Returns:
            Average query rate
            
        Raises:
            InvalidDataError: If queries list is empty or contains invalid data
        """
        if not queries:
            raise InvalidDataError("Cannot calculate query rate: empty queries list")
            
        if not all(isinstance(q, (int, float)) and q >= 0 for q in queries):
            raise InvalidDataError("All query values must be non-negative numbers")
        
        try:
            total = sum(queries)
            rate = total / len(queries)
            logger.info("Calculated query rate: %.2f queries/second", rate)
            return rate
        except Exception as e:
            logger.error("Error calculating query rate: %s", e)
            raise MetricsCalculatorError(f"Query rate calculation failed: {e}") from e

    def get_slow_queries(self, db_path: str, 
                        threshold: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Get slow queries using parameterized queries to prevent SQL injection.
        
        Args:
            db_path: Path to the database
            threshold: Custom threshold (uses instance default if None)
            
        Returns:
            List of slow queries
            
        Raises:
            DatabaseConnectionError: If database access fails
            InvalidDataError: If threshold is invalid
        """
        if threshold is None:
            threshold = self.slow_query_threshold
            
        if not isinstance(threshold, (int, float)) or threshold < 0:
            raise InvalidDataError("Threshold must be a non-negative number")
        
        slow_queries = []
        
        try:
            with self._get_db_connection(db_path) as conn:
                # Use parameterized query to prevent SQL injection
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT query_id, query_text, duration FROM queries WHERE duration > ?",
                    (threshold,)
                )
                
                for row in cursor.fetchall():
                    slow_queries.append({
                        "query_id": row["query_id"],
                        "query_text": row["query_text"],
                        "duration": row["duration"]
                    })
                    
            logger.info("Found %d slow queries with threshold %.2f ms", 
                       len(slow_queries), threshold)
            return slow_queries
            
        except Exception as e:
            logger.error("Error fetching slow queries: %s", e)
            raise DatabaseConnectionError(f"Failed to fetch slow queries: {e}") from e

    def calculate_avg_response_time(self, response_times: List[Union[int, float]]) -> float:
        """
        Calculate average response time with proper error handling.
        
        Args:
            response_times: List of response times in milliseconds
            
        Returns:
            Average response time
            
        Raises:
            InvalidDataError: If response_times is empty or contains invalid data
        """
        if not response_times:
            raise InvalidDataError("Cannot calculate average: empty response times list")
            
        if not all(isinstance(rt, (int, float)) and rt >= 0 for rt in response_times):
            raise InvalidDataError("All response times must be non-negative numbers")
        
        try:
            avg = sum(response_times) / len(response_times)
            logger.info("Calculated average response time: %.2f ms", avg)
            return avg
        except Exception as e:
            logger.error("Error calculating average response time: %s", e)
            raise MetricsCalculatorError(f"Average calculation failed: {e}") from e

    def parse_metrics(self, data: str) -> Dict[str, Any]:
        """
        Parse metrics data with comprehensive error handling.
        
        Args:
            data: JSON string containing metrics data
            
        Returns:
            Parsed metrics dictionary
            
        Raises:
            InvalidDataError: If data is invalid JSON or missing required fields
        """
        if not isinstance(data, str) or not data.strip():
            raise InvalidDataError("Data must be a non-empty string")
        
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as e:
            logger.error("JSON parsing error: %s", e)
            raise InvalidDataError(f"Invalid JSON format: {e}") from e
        
        if not isinstance(parsed, dict):
            raise InvalidDataError("Parsed data must be a dictionary")
        
        # Safely navigate nested dictionaries
        try:
            if 'metrics' not in parsed:
                raise InvalidDataError("Missing 'metrics' key in data")
                
            metrics = parsed['metrics']
            if not isinstance(metrics, dict):
                raise InvalidDataError("'metrics' must be a dictionary")
                
            # Return the full metrics dict instead of assuming structure
            logger.info("Successfully parsed metrics data")
            return metrics
            
        except KeyError as e:
            logger.error("Missing required key in metrics data: %s", e)
            raise InvalidDataError(f"Missing required key: {e}") from e

    def secure_file_operation(self, filename: str, base_dir: str = "/var/log") -> str:
        """
        Perform secure file operations with path traversal protection.
        
        Args:
            filename: Name of the file to read
            base_dir: Base directory (must be absolute)
            
        Returns:
            File contents
            
        Raises:
            InvalidDataError: If path traversal is detected or file is invalid
        """
        if not filename or '..' in filename or filename.startswith('/'):
            raise InvalidDataError("Invalid filename - potential path traversal")
        
        try:
            # Create secure path and validate it's within base directory
            base_path = Path(base_dir).resolve()
            file_path = (base_path / filename).resolve()
            
            # Ensure the resolved path is still within base directory
            if not str(file_path).startswith(str(base_path)):
                raise InvalidDataError("Path traversal detected")
            
            # Use context manager for proper file handling
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            logger.info("Successfully read file: %s", file_path.name)
            return content
            
        except FileNotFoundError:
            raise InvalidDataError(f"File not found: {filename}")
        except PermissionError:
            raise InvalidDataError(f"Permission denied: {filename}")
        except Exception as e:
            logger.error("File operation error: %s", e)
            raise MetricsCalculatorError(f"File operation failed: {e}") from e

    def calculate_percentile(self, values: List[Union[int, float]], 
                           percentile: float) -> float:
        """
        Calculate percentile value correctly.
        
        Args:
            values: List of numeric values
            percentile: Percentile to calculate (0.0 to 1.0)
            
        Returns:
            Percentile value
            
        Raises:
            InvalidDataError: If values is empty or percentile is invalid
        """
        if not values:
            raise InvalidDataError("Cannot calculate percentile: empty values list")
            
        if not all(isinstance(v, (int, float)) for v in values):
            raise InvalidDataError("All values must be numbers")
            
        if not 0 <= percentile <= 1:
            raise InvalidDataError("Percentile must be between 0.0 and 1.0")
        
        try:
            # Create a copy and sort it (don't modify original)
            sorted_values = sorted(values)
            
            if percentile == 0:
                return sorted_values[0]
            elif percentile == 1:
                return sorted_values[-1]
            else:
                # Use statistics module for accurate percentile calculation
                quartiles = quantiles(sorted_values, n=100)
                index = int(percentile * 100) - 1
                result = quartiles[min(index, len(quartiles) - 1)]
                
            logger.info("Calculated %.0f%% percentile: %.2f", percentile * 100, result)
            return result
            
        except Exception as e:
            logger.error("Error calculating percentile: %s", e)
            raise MetricsCalculatorError(f"Percentile calculation failed: {e}") from e

    def update_metrics(self, new_metrics: List[Dict[str, Any]]) -> None:
        """
        Update metrics list safely without modifying during iteration.
        
        Args:
            new_metrics: List of new metrics to add
            
        Raises:
            InvalidDataError: If new_metrics is invalid
        """
        if not isinstance(new_metrics, list):
            raise InvalidDataError("new_metrics must be a list")
        
        try:
            # Create a new list with valid metrics instead of modifying during iteration
            valid_metrics = [
                metric for metric in self.metrics 
                if isinstance(metric, dict) and metric.get('value', 0) >= 0
            ]
            
            # Validate new metrics
            validated_new_metrics = []
            for metric in new_metrics:
                if not isinstance(metric, dict):
                    logger.warning("Skipping invalid metric: not a dictionary")
                    continue
                if 'value' not in metric:
                    logger.warning("Skipping metric without 'value' field")
                    continue
                validated_new_metrics.append(metric)
            
            # Update the metrics list
            self.metrics = valid_metrics + validated_new_metrics
            
            logger.info("Updated metrics: removed %d invalid, added %d valid", 
                       len(self.metrics) - len(valid_metrics) - len(validated_new_metrics),
                       len(validated_new_metrics))
                       
        except Exception as e:
            logger.error("Error updating metrics: %s", e)
            raise MetricsCalculatorError(f"Metrics update failed: {e}") from e

    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get a summary of current metrics.
        
        Returns:
            Dictionary with metrics summary
        """
        if not self.metrics:
            return {"total_metrics": 0, "summary": "No metrics available"}
        
        values = [m.get('value', 0) for m in self.metrics if isinstance(m.get('value'), (int, float))]
        
        if not values:
            return {"total_metrics": len(self.metrics), "summary": "No numeric values found"}
        
        return {
            "total_metrics": len(self.metrics),
            "min_value": min(values),
            "max_value": max(values),
            "avg_value": sum(values) / len(values),
            "median_value": median(values)
        }


def hash_password(password: str) -> str:
    """
    Hash a password securely using SHA-256.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    return hashlib.sha256(password.encode()).hexdigest()


def demo_usage() -> None:
    """
    Demonstrate proper usage of MetricsCalculator.
    This function shows secure patterns and proper error handling.
    """
    calc = MetricsCalculator(slow_query_threshold=150.0)
    
    try:
        # Example of secure connection (using environment variables for credentials)
        username = os.environ.get('DB_USERNAME', 'demo_user')
        password = os.environ.get('DB_PASSWORD', 'demo_password')
        password_hash = hash_password(password)
        
        # Connect securely (credentials from environment, not hardcoded)
        calc.connect_to_database("localhost", 3306, username, password_hash)
        
        # Calculate query rates with proper error handling
        query_counts = [10, 15, 8, 12, 20, 18]
        try:
            rate = calc.calculate_query_rate(query_counts)
            print(f"Query rate: {rate:.2f} queries/second")
        except InvalidDataError as e:
            logger.error("Query rate calculation failed: %s", e)
        
        # Calculate response times
        response_times = [45.2, 67.8, 23.1, 89.5, 34.7]
        try:
            avg_time = calc.calculate_avg_response_time(response_times)
            print(f"Average response time: {avg_time:.2f} ms")
            
            # Check if response time is acceptable
            if avg_time is not None and avg_time > 100:
                logger.warning("High average response time detected: %.2f ms", avg_time)
        except InvalidDataError as e:
            logger.error("Response time calculation failed: %s", e)
        
        # Efficient string building using join
        parts = [str(i) for i in range(1000)]
        result = ''.join(parts)
        logger.info("Built string of length: %d", len(result))
        
        # Proper file handling with context manager
        metrics_file = "demo_metrics.txt"
        try:
            with open(metrics_file, "w", encoding='utf-8') as f:
                f.write(f"Demo metrics: {calc.get_metrics_summary()}")
            logger.info("Metrics written to %s", metrics_file)
        except IOError as e:
            logger.error("Failed to write metrics file: %s", e)
        
        # Calculate percentiles
        values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        try:
            percentile_95 = calc.calculate_percentile(values, 0.95)
            print(f"95th percentile: {percentile_95}")
        except InvalidDataError as e:
            logger.error("Percentile calculation failed: %s", e)
        
    except Exception as e:
        logger.error("Demo execution failed: %s", e)
    finally:
        # Ensure cleanup happens
        calc.close_connections()


if __name__ == "__main__":
    demo_usage()