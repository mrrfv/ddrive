const parseBasicAuth = require('../utils/basicAuth')

module.exports = ({ auth, publicAccess }) => async (req, reply, done) => {
    // If creds are not given skip this route
    if (!auth.user && !auth.pass) return
    // Check if route is public or not
    const { routeConfig: { ACCESS_TAGS } } = req
    if (ACCESS_TAGS && ACCESS_TAGS.includes(publicAccess)) return
    // Verify credentials
    const basicAuthorization = parseBasicAuth(req)
    const queryAuthorization = req.query && req.query.authusername && req.query.authpassword
        ? { user: req.query.authusername, pass: req.query.authpassword }
        : null
    // Variables that check if the user is authorized (basic or query)
    const isBasicAuthorized = basicAuthorization && basicAuthorization.user === auth.user && basicAuthorization.pass === auth.pass
    const isQueryAuthorized = queryAuthorization && queryAuthorization.user === auth.user && queryAuthorization.pass === auth.pass
    const isAuthorized = isBasicAuthorized || isQueryAuthorized
    // If not authorized throw error
    if (!isAuthorized) {
        // Throw error if invalid
        reply.header('WWW-Authenticate', 'Basic realm="Login"')
        const error = new Error('Missing or bad formatted authorization header or query parameters')
        error.statusCode = 401
        done(error)
    }
}
