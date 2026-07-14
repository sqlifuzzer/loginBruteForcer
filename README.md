# loginBruteForcer
Brute force login pages with the aptly-named loginBruteForcer. Designed from the ground up to be sneaky, fast, and easy to use.
# How Will I Know?
The legend Whitney Houston once asked: How will I know? She was, of course, asking if a certain person would love her. But this question also applies to automated brute forcing of login pages.

If you are not in possesion of a valid set of credentials, how will your script know if it has been have been successful? Will it respond with a 302 redirect to a post-auth landing page? Will the response length change? Presumably, the response body will be different to that of a failed authentication attempt. But how different?

LoginBruteForcer attempts to spot these changes, without knowing what they will be, by baselining various aspects of failed authentcation responses (status code, response length, response content, etc), and then comparing each login response to the baseline, while trying to handle some of the common fluctuations you can expect to see when you brute force a login page.
