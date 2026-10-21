export const RESPONSE_TYPES = {
	json: {
		kind: "json",
		mimeType: "application/json",
		label: "JSON",
		structuredSuffix: "+json",
	},
	jpeg: {
		kind: "image",
		mimeType: "image/jpeg",
		label: "JPEG image data",
		validate: (bytes: Uint8Array) => bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff,
	},
} as const;

const RESPONSE_FORMATS = {
	json: [RESPONSE_TYPES.json],
	"json-or-text": [RESPONSE_TYPES.json],
	"json-or-image": [RESPONSE_TYPES.json, RESPONSE_TYPES.jpeg],
} as const;

export type ResponseFormat = keyof typeof RESPONSE_FORMATS;

export type JsonResponseFormat = {
	[Format in ResponseFormat]: Extract<typeof RESPONSE_FORMATS[Format][number], { kind: "image" }> extends never ? Format : never;
}[ResponseFormat];

type ResponseType = typeof RESPONSE_TYPES[keyof typeof RESPONSE_TYPES];

export type ImageMimeType = Extract<ResponseType, { kind: "image" }>["mimeType"];

/** Parameters and malformed header values must never appear in connector errors. */
export function parseMediaType(contentType: string | null): string | undefined {
	const mediaType = contentType?.split(";", 1)[0].trim().toLowerCase();

	return mediaType && mediaType.length <= 127 &&
		/^[-!#$%&'*+.^_`|~0-9a-z]+\/[-!#$%&'*+.^_`|~0-9a-z]+$/.test(mediaType)
		? mediaType : undefined;
}

export function responseTypeFor(mediaType: string | undefined, format: ResponseFormat): ResponseType | undefined {
	return RESPONSE_FORMATS[format].find((type) => mediaType === type.mimeType ||
		(type.kind === "json" && mediaType?.startsWith("application/") && mediaType.endsWith(type.structuredSuffix)));
}

export function isImageMimeType(value: unknown): value is ImageMimeType {
	return Object.values(RESPONSE_TYPES).some((type) => type.kind === "image" && type.mimeType === value);
}

export function responseAccept(format: ResponseFormat = "json"): string {
	return RESPONSE_FORMATS[format].map((type) => type.mimeType).join(", ");
}

export function supportedResponseTypes(format: ResponseFormat): string {
	return RESPONSE_FORMATS[format].map((type) => type.kind === "json"
		? `${type.label} (${type.mimeType} or application/*${type.structuredSuffix})`
		: type.mimeType).join(" or ");
}
