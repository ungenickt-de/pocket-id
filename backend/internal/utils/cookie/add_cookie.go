package cookie

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func AddAccessTokenCookie(c *gin.Context, maxAgeInSeconds int, token string) {
	addCookie(c, AccessTokenCookieName, token, maxAgeInSeconds, "/")
}

func AddSessionIdCookie(c *gin.Context, maxAgeInSeconds int, sessionID string) {
	addCookie(c, SessionIdCookieName, sessionID, maxAgeInSeconds, "/")
}

func AddDeviceTokenCookie(c *gin.Context, deviceToken string) {
	addCookie(c, DeviceTokenCookieName, deviceToken, int(15*time.Minute.Seconds()), "/api/one-time-access-token")
}

func AddDeviceLoginTokenCookie(c *gin.Context, requestID, deviceToken string) {
	path := "/api/device-login/requests/" + requestID + "/exchange"
	addCookie(c, DeviceLoginTokenCookieName, deviceToken, int(15*time.Minute.Seconds()), path)
}

func AddReauthenticationTokenCookie(c *gin.Context, reauthenticationToken string) {
	addCookie(c, ReauthenticationTokenCookieName, reauthenticationToken, int(3*time.Minute.Seconds()), "/")
}

// AddIdentityProviderStateCookie stores the encrypted state of a sign-in with an external identity provider
// The cookie is scoped to the callback path, so it is only sent back when the identity provider redirects the browser to Pocket ID
func AddIdentityProviderStateCookie(c *gin.Context, maxAgeInSeconds int, path, value string) {
	addCookie(c, IdentityProviderStateCookieName, value, maxAgeInSeconds, path)
}

// ClearIdentityProviderStateCookie removes the identity provider state cookie so it cannot be replayed
func ClearIdentityProviderStateCookie(c *gin.Context, path string) {
	addCookie(c, IdentityProviderStateCookieName, "", -1, path)
}

func addCookie(c *gin.Context, name, value string, maxAge int, path string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, maxAge, path, "", true, true)
}
