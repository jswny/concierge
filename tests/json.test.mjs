import assert from "node:assert/strict";
import { test } from "node:test";
import { isJsonObject, parseJson } from "../src/json.ts";

test("JSON parsing preserves native values and unknown provider fields", () => {
	for (const text of ['null', 'false', '0', '-0', '1e400', '"text"', '[1, null, {"future": true}]', '{"next": "cursor", "unknown": {"items": []}}']) {
		assert.deepEqual(parseJson(text), JSON.parse(text));
	}
});

test("JSON parsing preserves special own keys without modifying prototypes", () => {
	const result = parseJson('{"__proto__": {"polluted": true}, "constructor": {"id": 1}}');
	assert.equal(Object.hasOwn(result, "__proto__"), true);
	assert.equal(Object.getPrototypeOf(result), Object.prototype);
	assert.deepEqual(Object.getOwnPropertyDescriptor(result, "__proto__").value, { polluted: true });
	assert.equal(Object.hasOwn({}, "polluted"), false);
});

test("JSON parsing retains native depth handling instead of recursively revalidating responses", () => {
	const depth = 2048;
	let value = parseJson(`${"[".repeat(depth)}null${"]".repeat(depth)}`);

	for (let index = 0; index < depth; index++) {
		assert.ok(Array.isArray(value));
		assert.equal(value.length, 1);
		value = value[0];
	}

	assert.equal(value, null);
});

test("JSON parsing rejects malformed data without inventing a payload", () => {
	for (const text of ["", "undefined", "[1,]", '{"x":', "<html>error</html>"]) {
		assert.throws(() => parseJson(text), SyntaxError);
	}
});

test("JSON object discrimination leaves already parsed data unchanged", () => {
	const value = parseJson('{"items": [1, null, {"native": true}], "future": false}');
	const before = JSON.stringify(value);
	assert.equal(isJsonObject(value), true);
	assert.equal(JSON.stringify(value), before);

	for (const scalar of [undefined, null, false, 0, "text", []]) {
		assert.equal(isJsonObject(scalar), false);
	}
});
