from src.classification.classifier import RuleBasedClassifier
import os

config_path = 'configs/classification_rules.json'
if not os.path.exists(config_path):
    # Try to find it if we are in a different dir
    config_path = os.path.join(os.getcwd(), 'configs', 'classification_rules.json')

classifier = RuleBasedClassifier(config_path)

test_html = '''
<html>
<head><title>Bitcoin Marketplace</title></head>
<body>
<h1>Welcome to our Market</h1>
<p>We sell various products. Price: 0.5 BTC</p>
<form action="/cart">Add to cart</form>
</body>
</html>
'''

result = classifier.classify(test_html, url='http://testmarket.onion')
print(f'Category: {result.category.value}')
print(f'Confidence: {result.confidence:.2f}')
print(f'Subcategory: {result.subcategory}')
