package org.scribe.extractors;

import java.net.URI;
import java.util.regex.*;

import org.scribe.exceptions.*;
import org.scribe.model.*;
import org.scribe.utils.*;

/**
 * Default implementation of {@AccessTokenExtractor}. Conforms to OAuth 2.0
 *
 */
public class TokenExtractor20Impl implements AccessTokenExtractor
{
  private static final String TOKEN_REGEX = "access_token=([^&]+)";
  private static final String EMPTY_SECRET = "";
  
  private static final Pattern ACCESS_TOKEN_REGEX_PATTERN = Pattern.compile("\"access_token\"\\s*:\\s*\"(\\S*?)\"");
  private static final Pattern TOKEN_TYPE_REGEX_PATTERN = Pattern.compile("\"token_type\"\\s*:\\s*\"(\\S*?)\"");
  private static final Pattern EXPIRES_IN_REGEX_PATTERN = Pattern.compile("\"expires_in\"\\s*:\\s*\"?(\\d*?)\"?\\D");
  private static final Pattern REFRESH_TOKEN_REGEX_PATTERN = Pattern.compile("\"refresh_token\"\\s*:\\s*\"(\\S*?)\"");
  private static final Pattern SCOPE_REGEX_PATTERN = Pattern.compile("\"scope\"\\s*:\\s*\"(\\S*?)\"");
  private static final Pattern ERROR_REGEX_PATTERN = Pattern.compile("\"error\"\\s*:\\s*\"(\\S*?)\"");
  private static final Pattern ERROR_DESCRIPTION_REGEX_PATTERN
          = Pattern.compile("\"error_description\"\\s*:\\s*\"([^\"]*?)\"");
  private static final Pattern ERROR_URI_REGEX_PATTERN = Pattern.compile("\"error_uri\"\\s*:\\s*\"(\\S*?)\"");

  /**
   * {@inheritDoc} 
   */
  public Token extract(String response)
  {
	  final String body = response;
      Preconditions.checkEmptyString(body,
              "Response body is incorrect. Can't extract a token from an empty string");
      
    if (!extractParameter(body, ACCESS_TOKEN_REGEX_PATTERN, true).equals(""))
    {
      String token = extractParameter(body, ACCESS_TOKEN_REGEX_PATTERN, true);
      return new Token(token, EMPTY_SECRET, body);
    } 
    else
    {
      throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
    }
  }
  /**
   * Related documentation: https://tools.ietf.org/html/rfc6749#section-5.2
   *
   * @param response response
   */
  protected void generateError(String response) {
      final String errorInString = extractParameter(response, ERROR_REGEX_PATTERN, true);
      final String errorDescription = extractParameter(response, ERROR_DESCRIPTION_REGEX_PATTERN, false);
      final String errorUriInString = extractParameter(response, ERROR_URI_REGEX_PATTERN, false);
      URI errorUri;
      try {
          errorUri = errorUriInString == null ? null : URI.create(errorUriInString);
      } catch (IllegalArgumentException iae) {
          errorUri = null;
      }
      throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response 
    		  + "' because description: " + errorDescription + " and uri: " + errorUri 
    		  + " and String: " + errorInString, null);
  }

  protected static String extractParameter(String response, Pattern regexPattern, boolean required)
          throws OAuthException {
      final Matcher matcher = regexPattern.matcher(response);
      if (matcher.find()) {
          return matcher.group(1);
      }

      if (required) {
          throw new OAuthException("Response body is incorrect. Can't extract a '" + regexPattern.pattern()
                  + "' from this: '" + response + "'", null);
      }

      return null;
  }
}
