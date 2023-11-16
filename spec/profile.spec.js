/*
 * Test suite for profile
 */
require("es6-promise").polyfill();
require("isomorphic-fetch");

const url = (path) => `http://localhost:3000${path}`;
let cookie;

describe("Validate Profile functionality", () => {
  it("should return headline for logged in user", (done) => {
    fetch(url("/headline"), {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    })
      .then((res) => res.json())
      .then((res) => {
        expect(res.username).toBe('RDesRoches');
        expect(res.headline).toBe('This is my headline!');
        done();
      });
  });

  it("should update headline for logged in user", (done) => {
    fetch(url("/headline"), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ headline: newHeadline })
    })
      .then((res) => res.json())
      .then((res) => {
        expect(res.username).toBe('RDesRoches');
        expect(res.headline).toBe(newHeadline);
        done();
      })
      .catch((err) => done(err));
  });
});
