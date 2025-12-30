import asyncio
from src.classification.pipeline import ClassificationPipeline

async def test():
    pipeline = ClassificationPipeline()
    
    test_content = '''
    <html>
    <title>Dark Web Forum</title>
    <body>
    <h1>Welcome to our forum</h1>
    <p>Discuss various topics here.</p>
    <a href="/register">Register</a>
    <a href="/login">Login</a>
    </body>
    </html>
    '''
    
    result = await pipeline.process(
        url='http://testforum.onion',
        content=test_content,
        content_type_hint='text/html',
    )
    
    print(f'Safe: {result.is_safe}')
    print(f'Category: {result.classification_result.category.value if result.classification_result else "None"}')
    print(f'Risk: {result.risk_score.level.value if result.risk_score else "None"}')

if __name__ == "__main__":
    asyncio.run(test())
