import unittest
from analyzer import format_timestamp

class TestAnalyzer(unittest.TestCase):
    
    def test_format_timestamp_standard(self):
        """Test timestamp conversion with typical milliseconds."""
        # Raw epoch time for: 2026-07-07 10:30:00.123
        raw_ts = 1783420200.123 
        expected = "2026-07-07T10:30:00.123Z"
        
        result = format_timestamp(raw_ts)
        self.assertEqual(result, expected, "The timestamp was not formatted correctly!")

    def test_format_timestamp_zero_milliseconds(self):
        """Test timestamp conversion when milliseconds are exactly zero."""
        # Raw epoch time for: 2026-07-07 10:30:00.000
        raw_ts = 1783420200.0 
        expected = "2026-07-07T10:30:00.000Z"
        
        result = format_timestamp(raw_ts)
        self.assertEqual(result, expected, "Failed to handle zero milliseconds correctly!")

if __name__ == '__main__':
    unittest.main()
