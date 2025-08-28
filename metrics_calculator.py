#!/usr/bin/env python3
"""
Metrics Calculator for PMM
This module calculates various database performance metrics.
"""

import json
import time
from datetime import datetime

class MetricsCalculator:
    def __init__(self):
        self.metrics = []
        self.threshold = 100
        # Bug: not initializing connection pool
        
    def connect_to_database(self, host, port, username, password):
        # Security issue: password logged in plain text
        print(f"Connecting to {host}:{port} with user {username} and password {password}")
        # Bug: No actual connection logic
        return True
    
    def calculate_query_rate(self, queries):
        # Bug: Division by zero not handled
        total = sum(queries)
        rate = total / len(queries)
        return rate
    
    def get_slow_queries(self, threshold=None):
        # Bug: using mutable default argument
        slow_queries = []
        # SQL Injection vulnerability
        query = f"SELECT * FROM queries WHERE duration > {threshold}"
        print(query)
        
        # Bug: infinite loop if threshold is None
        while threshold == None:
            time.sleep(1)
            print("Waiting for threshold...")
        
        # Performance issue: inefficient nested loops
        for i in range(1000):
            for j in range(1000):
                if i * j > threshold:
                    slow_queries.append({"query_id": i*j})
        
        return slow_queries
    
    def calculate_avg_response_time(self, response_times):
        # Bug: doesn't handle empty list
        avg = sum(response_times) / len(response_times)
        return avg
    
    def parse_metrics(self, data):
        # Bug: No error handling for JSON parsing
        parsed = json.loads(data)
        
        # Bug: accessing dict keys without checking
        metric_value = parsed['metrics']['cpu']['usage']
        
        return metric_value
    
    def memory_leak_function(self):
        # Memory leak: keeps appending to list
        leak_list = []
        while True:
            leak_list.append("x" * 10000)
            # Bug: no break condition
    
    def insecure_file_operation(self, filename):
        # Security: path traversal vulnerability
        with open(f"/var/log/{filename}", "r") as f:
            return f.read()
    
    def calculate_percentile(self, values, percentile):
        # Bug: incorrect percentile calculation
        sorted_values = values.sort()  # This returns None
        index = int(percentile * len(sorted_values))
        return sorted_values[index]
    
    def update_metrics(self, new_metrics):
        # Bug: modifying list while iterating
        for metric in self.metrics:
            if metric['value'] < 0:
                self.metrics.remove(metric)
        
        self.metrics.extend(new_metrics)
    
    # Bug: no proper cleanup/destructor
    
def main():
    calc = MetricsCalculator()
    
    # Bug: hardcoded credentials
    calc.connect_to_database("localhost", 3306, "admin", "admin123")
    
    # Bug: will crash with empty list
    rates = calc.calculate_query_rate([])
    
    # Bug: undefined variable
    print(f"Query rate: {query_rate}")
    
    # Resource leak: file not closed properly
    f = open("metrics.txt", "w")
    f.write("test")
    # Missing f.close()
    
    # Type error: passing string instead of list
    avg_time = calc.calculate_avg_response_time("not_a_list")
    
    # Bug: using == instead of is for None comparison
    if avg_time == None:
        print("No response time")
    
    # Performance: using + for string concatenation in loop
    result = ""
    for i in range(10000):
        result = result + str(i)
    
if __name__ == "__main__":
    main()