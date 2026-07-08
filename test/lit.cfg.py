import lit.formats

config.name = "wrela"
config.test_format = lit.formats.ShTest(True)
config.suffixes = [".wrela"]
config.test_source_root = os.path.dirname(__file__)
