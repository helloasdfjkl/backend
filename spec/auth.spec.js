/*
 * Test suite for profile
 */
require("es6-promise").polyfill();
require("isomorphic-fetch");

const url = (path) => `http://localhost:3000${path}`;
let cookie;

describe("Validate Registration and Login functionality", () => {
  beforeEach((done) => {
    //register a new user
    fetch(url("/register"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "RDesRoches", password: "123" }),
    })
      .then((res) => {
        cookie = res.headers.get("Set-Cookie");
        return res.json();
      })
      .then((res) => {
        registeredUser = res;
        done();
      });
  });

  it("should register new user", (done) => {
    fetch(url("/register"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    })
      .then((res) => res.json())
      .then((res) => {
        expect(res.username).toBe("RDesRoches");
        done();
      })
      .catch((err) => done(err));
  });

  it("should log in user", (done) => {
    fetch(url("/login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ headline: newHeadline }),
    })
      .then((res) => res.json())
      .then((res) => {
        expect(res.username).toBe("RDesRoches");
        expect(res.headline).toBe(newHeadline);
        done();
      })
      .catch((err) => done(err));
  });

  it("should log out current logged in user", (done) => {
    fetch(url("/login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "RDesRoches", password: "123" }),
    })
      .then((res) => res.json())
      .then(() => {
        fetch(url("/logout"), {
          method: "PUT",
          headers: { "Content-Type": "application/json", Cookie: cookie }, // Pass the session cookie
          body: JSON.stringify({}),
        })
          .then((res) => res.json())
          .then((res) => {
            expect(res.result).toBe("Logged out successfully");
            done();
          })
          .catch((err) => done(err));
      });
  });
});
