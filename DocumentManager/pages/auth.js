/* SecureDocs authentication helper.
   Visual/UI code stays in each page; this file only handles the server session. */
(function (window) {
    "use strict";

    var CACHE_KEY = "auth_user";
    var ROLE_PAGES = {
        admin: ["overview","documents","search","assistant","users","roles","audit","settings","profile"],
        executive: ["overview","documents","search","assistant","profile"],
        visitor: ["overview","documents","search","profile"]
    };

    function getCachedUser() {
        try {
            var raw = localStorage.getItem(CACHE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function setCachedUser(user) {
        if (!user) return;
        try {
            localStorage.setItem(CACHE_KEY, JSON.stringify({
                email: user.email || "",
                name: user.full_name || user.name || "User",
                role: user.role || "visitor",
                initials: ((user.full_name || user.name || "User").split(/\s+/).filter(Boolean).map(function (x) { return x.charAt(0); }).join("").slice(0, 2).toUpperCase()) || "U",
                csrf: user.csrf || "",
                loginAt: Date.now()
            }));
        } catch (e) {}
    }

    function clearCachedUser() {
        try { localStorage.removeItem(CACHE_KEY); } catch (e) {}
    }

    function init() {
        return fetch("/api/me", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store"
        }).then(function (response) {
            if (response.status === 401 || response.status === 403) {
                clearCachedUser();
                var error = new Error("AUTH_REQUIRED");
                error.status = response.status;
                throw error;
            }
            if (!response.ok) {
                var serverError = new Error("AUTH_SERVER_ERROR");
                serverError.status = response.status;
                throw serverError;
            }
            return response.json();
        }).then(function (user) {
            setCachedUser(user);
            window.currentUser = user;
            window.CSRF = user.csrf || null;
            return user;
        });
    }

    function login(email, password) {
        return fetch("/api/auth", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            cache: "no-store",
            body: JSON.stringify({ email: email, password: password })
        }).then(function (response) {
            return response.json().catch(function () { return {}; }).then(function (data) {
                if (!response.ok) {
                    var error = new Error(data.detail || "Unable to sign in.");
                    error.status = response.status;
                    throw error;
                }
                return data;
            });
        }).then(function () {
            return init();
        });
    }

    function request(url, options) {
        options = options || {};
        options.credentials = "same-origin";
        options.cache = options.cache || "no-store";
        options.headers = options.headers || {};
        var csrf = window.CSRF || (getCachedUser() || {}).csrf || "";
        if (csrf && !options.headers["X-CSRF"] && !options.headers["x-csrf"]) {
            options.headers["X-CSRF"] = csrf;
        }
        return fetch(url, options).then(function (response) {
            if (response.status === 401 || response.status === 403) {
                clearCachedUser();
            }
            return response;
        });
    }

    function logout() {
        var csrf = window.CSRF || (getCachedUser() || {}).csrf || "";
        return fetch("/api/logout", {
            method: "POST",
            credentials: "same-origin",
            headers: csrf ? { "X-CSRF": csrf } : {},
            cache: "no-store"
        }).catch(function () {
            /* Redirect even if the server is temporarily unavailable. */
        }).then(function () {
            clearCachedUser();
            window.currentUser = null;
            window.CSRF = null;
            window.location.replace("login.html");
        });
    }

    function guard(role) {
        return init().then(function (user) {
            if (role && role !== user.role) {
                window.location.replace("dashboard.html");
                return null;
            }
            return user;
        }).catch(function (error) {
            if (error && error.message === "AUTH_REQUIRED") {
                window.location.replace("login.html");
                return null;
            }
            console.error("SecureDocs authentication check failed:", error);
            return null;
        });
    }

    window.SecureDocsAuth = {
        getCachedUser: getCachedUser,
        setCachedUser: setCachedUser,
        clearCachedUser: clearCachedUser,
        init: init,
        login: login,
        request: request,
        logout: logout,
        guard: guard,
        ROLE_PAGES: ROLE_PAGES
    };
})(window);
