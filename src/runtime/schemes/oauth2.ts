import { ExpiredAuthSessionError, IdToken, RefreshController, RefreshToken, RequestHandler, Token } from "../inc/index.mjs";
import { getProp, normalizePath, parseQuery, randomString, removeTokenPrefix } from "../../utils";
import { joinURL, withQuery } from "ufo";
import { useRoute, useRuntimeConfig } from "#imports";

import { BaseScheme } from "./base.mjs";
import requrl from "requrl";

const DEFAULTS = {
  name: "oauth2",
  accessType: void 0,
  redirectUri: void 0,
  logoutRedirectUri: void 0,
  clientId: void 0,
  clientSecretTransport: "body",
  audience: void 0,
  grantType: void 0,
  responseMode: void 0,
  acrValues: void 0,
  autoLogout: false,
  idToken: {
    property: "id_token",
    maxAge: 1800,
    prefix: "_id_token.",
    expirationPrefix: "_id_token_expiration."
  },
  endpoints: {
    logout: void 0,
    authorization: void 0,
    token: void 0,
    userInfo: void 0
  },
  scope: [],
  token: {
    property: "access_token",
    type: "Bearer",
    name: "Authorization",
    maxAge: 1800,
    global: true,
    prefix: "_token.",
    expirationPrefix: "_token_expiration."
  },
  refreshToken: {
    property: "refresh_token",
    maxAge: 60 * 60 * 24 * 30,
    prefix: "_refresh_token.",
    expirationPrefix: "_refresh_token_expiration."
  },
  user: {
    property: false
  },
  responseType: "token",
  codeChallengeMethod: "implicit",
  clientWindow: false,
  clientWindowWidth: 400,
  clientWindowHeight: 600
};
export class Oauth2Scheme extends BaseScheme {
  constructor($auth, options, ...defaults) {
    super($auth, options, ...defaults, DEFAULTS);
    this.req = process.server ? $auth.ctx.ssrContext.event.node.req : void 0;
    this.idToken = new IdToken(this, this.$auth.$storage);
    this.token = new Token(this, this.$auth.$storage);
    this.refreshToken = new RefreshToken(this, this.$auth.$storage);
    this.refreshController = new RefreshController(this);
    this.requestHandler = new RequestHandler(this, this.$auth.ctx.$http);
    this.#clientWindowReference = null;
  }
  #clientWindowReference;
  get scope() {
    return Array.isArray(this.options.scope) ? this.options.scope.join(" ") : this.options.scope;
  }
  get redirectURI() {
    const basePath = useRuntimeConfig().app.baseURL || "";
    const path = normalizePath(basePath + "/" + this.$auth.options.redirect.callback);
    return this.options.redirectUri || joinURL(requrl(this.req), path);
  }
  get logoutRedirectURI() {
    return this.options.logoutRedirectUri || joinURL(requrl(this.req), this.$auth.options.redirect.logout);
  }
  check(checkStatus = false) {
    const response = {
      valid: false,
      tokenExpired: false,
      refreshTokenExpired: false,
      isRefreshable: true,
      idTokenExpired: false,
    };
    const token = this.token.sync();
    this.refreshToken.sync();
    this.idToken.sync();
    if (!token) {
      return response;
    }
    if (!checkStatus) {
      response.valid = true;
      return response;
    }
    const tokenStatus = this.token.status();
    const refreshTokenStatus = this.refreshToken.status();
    const idTokenStatus = this.idToken.status();
    if (refreshTokenStatus.expired()) {
      response.refreshTokenExpired = true;
      return response;
    }
    if (tokenStatus.expired()) {
      response.tokenExpired = true;
      return response;
    }
    if (idTokenStatus.expired()) {
      response.idTokenExpired = true;
      return response;
    }
    response.valid = true;
    return response;
  }
  async mounted() {
    const { tokenExpired, refreshTokenExpired } = this.check(true);
    if (refreshTokenExpired || tokenExpired && this.options.autoLogout) {
      this.$auth.reset();
    }
    this.requestHandler.initializeRequestInterceptor(
      this.options.endpoints.token
    );
    const redirected = await this.#handleCallback();
    if (!redirected) {
      return this.$auth.fetchUserOnce();
    }
  }
  reset() {
    this.$auth.setUser(false);
    this.token.reset();
    this.refreshToken.reset();
    this.requestHandler.reset();
    this.idToken.reset();
  }
  async login($opts = {}) {
    const opts = {
      protocol: "oauth2",
      response_type: this.options.responseType,
      access_type: this.options.accessType,
      client_id: this.options.clientId,
      redirect_uri: this.redirectURI,
      scope: this.scope,
      state: $opts.state || randomString(10),
      code_challenge_method: this.options.codeChallengeMethod,
      clientWindow: this.options.clientWindow,
      clientWindowWidth: this.options.clientWindowWidth,
      clientWindowHeight: this.options.clientWindowHeight,
      ...$opts.params
    };
    if (this.options.organization) {
      opts.organization = this.options.organization;
    }
    if (this.options.audience) {
      opts.audience = this.options.audience;
    }
    if (opts.clientWindow) {
      if (this.#clientWindowReference === null || this.#clientWindowReference?.closed) {
        const windowFeatures = this.clientWindowFeatures(opts.clientWindowWidth, opts.clientWindowHeight);
        this.#clientWindowReference = globalThis.open("about:blank", "oauth2-client-window", windowFeatures);
        let strategy = this.$auth.$state.strategy;
        let listener = this.clientWindowCallback.bind(this);
        globalThis.addEventListener("message", listener);
        let checkPopUpInterval = setInterval(() => {
          if (this.#clientWindowReference?.closed || strategy !== this.$auth.$state.strategy) {
            globalThis.removeEventListener("message", listener);
            this.#clientWindowReference = null;
            clearInterval(checkPopUpInterval);
          }
        }, 500);
      } else {
        this.#clientWindowReference.focus();
      }
    }
    if (opts.response_type.includes("token") || opts.response_type.includes("id_token")) {
      opts.nonce = $opts.nonce || randomString(10);
    }
    if (opts.code_challenge_method) {
      switch (opts.code_challenge_method) {
        case "plain":
        case "S256":
          {
            const state = this.generateRandomString();
            this.$auth.$storage.setUniversal(this.name + ".pkce_state", state);
            const codeVerifier = this.generateRandomString();
            this.$auth.$storage.setUniversal(this.name + ".pkce_code_verifier", codeVerifier);
            const codeChallenge = await this.pkceChallengeFromVerifier(codeVerifier, opts.code_challenge_method === "S256");
            opts.code_challenge = globalThis.encodeURIComponent(codeChallenge);
          }
          break;
        case "implicit":
        default:
          break;
      }
    }
    if (this.options.responseMode) {
      opts.response_mode = this.options.responseMode;
    }
    if (this.options.acrValues) {
      opts.acr_values = this.options.acrValues;
    }
    this.$auth.$storage.setUniversal(this.name + ".state", opts.state);
    const url = withQuery(this.options.endpoints.authorization, opts);
    if (opts.clientWindow) {
      if (this.#clientWindowReference) {
        this.#clientWindowReference.location = url;
      }
    } else {
      globalThis.location.replace(url);
    }
  }
  clientWindowCallback(event) {
    const isLogInSuccessful = !!event.data.isLoggedIn;
    if (isLogInSuccessful) {
      this.$auth.fetchUserOnce();
    }
  }
  clientWindowFeatures(clientWindowWidth, clientWindowHeight) {
    const top = globalThis.top.outerHeight / 2 + globalThis.top.screenY - clientWindowHeight / 2;
    const left = globalThis.top.outerWidth / 2 + globalThis.top.screenX - clientWindowWidth / 2;
    return `toolbar=no, menubar=no, width=${clientWindowWidth}, height=${clientWindowHeight}, top=${top}, left=${left}`;
  }
  logout() {
    if (this.options.endpoints.logout) {
      const opts = {
        id_token_hint: this.idToken.get(),
        post_logout_redirect_uri: this.logoutRedirectURI
      };
      const url = withQuery(this.options.endpoints.logout, opts);
      window.location.replace(url);
    }
    return this.$auth.reset();
  }
  async fetchUser() {
    if (!this.check().valid) {
      return;
    }
    if (!this.options.fetchRemote && this.idToken.get()) {
      const data2 = this.idToken.userInfo();
      this.$auth.setUser(data2);
      return;
    }
    if (!this.options.endpoints.userInfo) {
      this.$auth.setUser({});
      return;
    }
    const response = await this.$auth.requestWith({
      url: this.options.endpoints.userInfo
    });
    this.$auth.setUser(getProp(response, this.options.user.property));
  }
  async #handleCallback() {
    const route = useRoute();
    if (this.$auth.options.redirect && normalizePath(route.path) !== normalizePath(this.$auth.options.redirect.callback)) {
      return;
    }
    if (process.server) {
      return;
    }
    const hash = parseQuery(route.hash.slice(1));
    const parsedQuery = Object.assign({}, route.query, hash);
    let token = parsedQuery[this.options.token.property];
    let refreshToken;
    if (this.options.refreshToken.property) {
      refreshToken = parsedQuery[this.options.refreshToken.property];
    }
    let idToken = parsedQuery[this.options.idToken.property];
    const state = this.$auth.$storage.getUniversal(this.name + ".state");
    this.$auth.$storage.setUniversal(this.name + ".state", null);
    if (state && parsedQuery.state !== state) {
      return;
    }
    if (this.options.responseType.includes("code") && parsedQuery.code) {
      let codeVerifier;
      if (this.options.codeChallengeMethod && this.options.codeChallengeMethod !== "implicit") {
        codeVerifier = this.$auth.$storage.getUniversal(this.name + ".pkce_code_verifier");
        this.$auth.$storage.setUniversal(this.name + ".pkce_code_verifier", null);
      }
      const response = await this.$auth.request({
        method: "post",
        url: this.options.endpoints.token,
        baseURL: "",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code: parsedQuery.code,
          client_id: this.options.clientId,
          redirect_uri: this.redirectURI,
          response_type: this.options.responseType,
          audience: this.options.audience,
          grant_type: this.options.grantType,
          code_verifier: codeVerifier
        })
      });
      token = getProp(response, this.options.token.property) || token;
      refreshToken = getProp(response, this.options.refreshToken.property) || refreshToken;
      idToken = getProp(response, this.options.idToken.property) || idToken;
    }
    if (!token || !token.length) {
      return;
    }
    this.token.set(token);
    if (refreshToken && refreshToken.length) {
      this.refreshToken.set(refreshToken);
    }
    if (idToken && idToken.length) {
      this.idToken.set(idToken);
    }
    if (this.options.clientWindow) {
      if (globalThis.opener) {
        globalThis.opener.postMessage({ isLoggedIn: true });
        globalThis.close();
      }
    } else if (this.$auth.options.watchLoggedIn) {
      this.$auth.redirect("home", false, false);
      return true;
    }
  }
  async refreshTokens() {
    const refreshToken = this.refreshToken.get();
    if (!refreshToken) {
      return;
    }
    const refreshTokenStatus = this.refreshToken.status();
    if (refreshTokenStatus.expired()) {
      this.$auth.reset();
      throw new ExpiredAuthSessionError();
    }
    this.requestHandler.clearHeader();
    const response = await this.$auth.request({
      method: "post",
      url: this.options.endpoints.token,
      baseURL: "",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        refresh_token: removeTokenPrefix(refreshToken, this.options.token.type),
        scope: this.scope,
        client_id: this.options.clientId,
        grant_type: "refresh_token"
      })
    }).catch((error) => {
      this.$auth.callOnError(error, { method: "refreshToken" });
      return Promise.reject(error);
    });
    this.updateTokens(response);
    return response;
  }
  updateTokens(response) {
    const token = getProp(response, this.options.token.property);
    const refreshToken = getProp(response, this.options.refreshToken.property);
    this.token.set(token);
    const idToken = getProp(response, this.options.idToken.property);
    if (idToken) {
      this.idToken.set(idToken);
    }
    if (refreshToken) {
      this.refreshToken.set(refreshToken);
    }
  }
  async pkceChallengeFromVerifier(v, hashValue) {
    if (hashValue) {
      const hashed = await this.#sha256(v);
      return this.#base64UrlEncode(hashed);
    }
    return v;
  }
  generateRandomString() {
    const array = new Uint32Array(28);
    globalThis.crypto.getRandomValues(array);
    return Array.from(array, (dec) => ("0" + dec.toString(16)).slice(-2)).join("");
  }
  #sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return globalThis.crypto.subtle.digest("SHA-256", data);
  }
  #base64UrlEncode(str) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
}
