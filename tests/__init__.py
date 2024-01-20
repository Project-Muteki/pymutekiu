import unittest

def run_all():
    loader = unittest.TestLoader()
    suite = loader.discover('.')
    runner = unittest.TextTestRunner()
    runner.run(suite)

