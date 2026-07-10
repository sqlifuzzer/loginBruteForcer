# loginBruteForcer
Brute force login pages with the aptly-named loginBruteForcer. Designed from the ground up to be sneaky, fast, and easy to use.
# How Will I Know
The legend Whitney Houston once asked: How will I know? She was, of course, aksing if a certain person would love her. But this question also applies to automated brute forcing of login pages; specifically:

If you are not in possesion of a valid set of credentials, how will you know if you have been successful. You can see how the application behaves when you provide invalid credentials, but you don't know how the application will behave when valid credentials are submitted. Will it 302 you to a post-auth landing page? Will the response length change? Presumably, the response body will be different to that of a failed authentication attempt. But how different?

LoginBruteForcer attempts to spot these changes without knowing what they will be by baselining the usual aspects of a  failed authentcation response (status code, response length, response content, etc), and then comparing each result from the main brute forcing loop to the baseline and being smart about the usual fluctuations you can expect to see when you brute force a login page.
